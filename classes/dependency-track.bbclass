# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

DEPENDENCYTRACK_DIR ??= "${DEPLOY_DIR}/dependency-track"
DEPENDENCYTRACK_SBOM ??= "${DEPENDENCYTRACK_DIR}/bom.json"
DEPENDENCYTRACK_VEX ??= "${DEPENDENCYTRACK_DIR}/vex.json"
DEPENDENCYTRACK_TMP ??= "${TMPDIR}/dependency-track"
DEPENDENCYTRACK_LOCK ??= "${DEPENDENCYTRACK_TMP}/bom.lock"

# Set DEPENDENCYTRACK_UPLOAD to False if you want to control the upload in other
# steps.
DEPENDENCYTRACK_UPLOAD ??= "True"
DEPENDENCYTRACK_PROJECT ??= ""
DEPENDENCYTRACK_API_URL ??= ""
DEPENDENCYTRACK_API_KEY ??= ""
DEPENDENCYTRACK_SBOM_PROCESSING_TIMEOUT ??= "1200"

DT_LICENSE_CONVERSION_MAP ??= '{ "GPLv2+" : "GPL-2.0-or-later", "GPLv2" : "GPL-2.0", "LGPLv2" : "LGPL-2.0", "LGPLv2+" : "LGPL-2.0-or-later", "LGPLv2.1+" : "LGPL-2.1-or-later", "LGPLv2.1" : "LGPL-2.1"}'

python do_dependencytrack_init() {
    import uuid
    from datetime import datetime

    timestamp = datetime.now().astimezone().isoformat()
    bom_serial_number = str(uuid.uuid4())
    dependencytrack_dir = d.getVar("DEPENDENCYTRACK_DIR")
    bb.debug(2, "Creating dependencytrack directory: %s" % dependencytrack_dir)
    bb.utils.mkdirhier(dependencytrack_dir)
    bb.debug(2, "Creating empty sbom")
    write_json(d.getVar("DEPENDENCYTRACK_SBOM"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{bom_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp
        },
        "components": []
    })

    bb.debug(2, "Creating empty patched CVEs VEX file")
    write_json(d.getVar("DEPENDENCYTRACK_VEX"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().astimezone().replace(microsecond=0).isoformat(),
        },
        "vulnerabilities": []
    })
}

addhandler do_dependencytrack_init
do_dependencytrack_init[eventmask] = "bb.event.BuildStarted"

python do_dependencytrack_collect() {
    import json
    import uuid
    import oe.cve_check
    from pathlib import Path

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_json(d.getVar("DEPENDENCYTRACK_SBOM"))
    vex = read_json(d.getVar("DEPENDENCYTRACK_VEX"))

    # update it with the new package info
    names = name.split()
    for index, cpe in enumerate(oe.cve_check.get_cpe_ids(name, version)):
        bb.debug(2, f"Collecting pagkage {name}@{version} ({cpe})")
        if not next((c for c in sbom["components"] if c["cpe"] == cpe), None):
            product = names[index]
            if ":" in product:
                vendor, product = product.split(":", 1)
            else:
                vendor = None

            bom_ref = str(uuid.uuid4())

            comp = {
                "name": product,
                "version": version,
                "cpe": cpe,
                "type": "library",
                "bom-ref": bom_ref
            }
            if vendor is not None:
                comp["publisher"] = vendor # published is closest to vendor

            license_json = get_licenses(d)
            if license_json:
                comp["licenses"] = license_json

            sbom["components"].append(comp)

            # populate vex file with patched CVEs
            for _, patched_cve in enumerate(oe.cve_check.get_patched_cves(d)):
                bb.debug(2, f"Found patch for CVE {patched_cve} in {name}@{version}")
                vex["vulnerabilities"].append({
                    "id": patched_cve,
                    # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
                    # this should always be NVD for yocto CVEs.
                    "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
                    "analysis": {"state": "resolved"},
                    # ref needs to be in bom-link format, however the uuid does not actually have to match the SBOM document uuid,
                    # see https://github.com/DependencyTrack/dependency-track/issues/1872#issuecomment-1254265425
                    # This is not ideal, as "resolved" will be applied to all components within the project containing the CVE,
                    # however component specific resolving seems not to work at the moment.
                    "affects": [{"ref": f"urn:cdx:{str(uuid.uuid4())}/1#{bom_ref}"}]
                })
            # populate vex file with ignored CVEs defined in CVE_CHECK_IGNORE
            # TODO: In newer versions of Yocto CVE_CHECK_IGNORE is deprecated in favour of CVE_STATUS, which we should also take into account here
            cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
            if cve_check_ignore is not None:
                for ignored_cve in cve_check_ignore.split():
                    bb.debug(2, f"Found ignore statement for CVE {ignored_cve} in {name}@{version}")
                    vex["vulnerabilities"].append({
                        "id": ignored_cve,
                        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
                        # this should always be NVD for yocto CVEs.
                        "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
                        # setting not-affected state for ignored CVEs
                        "analysis": {"state": "not_affected"},
                        # ref needs to be in bom-link format, however the uuid does not actually have to match the SBOM document uuid,
                        # see https://github.com/DependencyTrack/dependency-track/issues/1872#issuecomment-1254265425
                        # This is not ideal, as "resolved" will be applied to all components within the project containing the CVE,
                        # however component specific resolving seems not to work at the moment.
                        "affects": [{"ref": f"urn:cdx:{str(uuid.uuid4())}/1#{bom_ref}"}]
                    })
    # write it back to the deploy directory
    write_json(d.getVar("DEPENDENCYTRACK_SBOM"), sbom)
    write_json(d.getVar("DEPENDENCYTRACK_VEX"), vex)
}

addtask dependencytrack_collect before do_build after do_fetch
do_dependencytrack_collect[nostamp] = "1"
do_dependencytrack_collect[lockfiles] += "${DEPENDENCYTRACK_LOCK}"
do_rootfs[recrdeptask] += "do_dependencytrack_collect"

python do_dependencytrack_upload () {
    import json
    import base64
    import urllib
    import time
    from pathlib import Path

    if d.getVar("DEPENDENCYTRACK_API_URL") == "":
        bb.debug(2, f"Not uploading to Dependency Track, no API URL set in {var_api_url}")
        return

    dt_upload = bb.utils.to_boolean(d.getVar('DEPENDENCYTRACK_UPLOAD'))
    if not dt_upload:
        return

    sbom_path = d.getVar("DEPENDENCYTRACK_SBOM")
    vex_path  = d.getVar("DEPENDENCYTRACK_VEX")
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_sbom_url = f"{d.getVar('DEPENDENCYTRACK_API_URL')}/v1/bom"
    dt_vex_url = f"{d.getVar('DEPENDENCYTRACK_API_URL')}/v1/vex"


    # Uploading works either with method PUT and Content-Type: application/json (limited to 20MB)
    # or with method POST and Content-Type: multipart/form-data (no limit in size).
    # see https://docs.dependencytrack.org/usage/cicd/#cyclonedx
    # We will use the latter, but we're working with standard libraries only 
    # and urllib does not support multipart/form-data ootb.
    # So we need to manually construct the body of the upload request.
    # see https://pymotw.com/3/urllib.request/#uploading-files

    import io
    import mimetypes
    import uuid

    class MultiPartForm:
        """Accumulate the data to be used when posting a form."""

        def __init__(self):
            self.form_fields = []
            self.files = []
            # Use a large random byte string to separate
            # parts of the MIME data.
            self.boundary = uuid.uuid4().hex.encode('utf-8')
            return

        def get_content_type(self):
            return 'multipart/form-data; boundary={}'.format(
                self.boundary.decode('utf-8'))

        def add_field(self, name, value):
            """Add a simple field to the form data."""
            self.form_fields.append((name, value))

        def add_file(self, fieldname, filename, fileHandle,
                    mimetype=None):
            """Add a file to be uploaded."""
            body = fileHandle.read()
            if mimetype is None:
                mimetype = (
                    mimetypes.guess_type(filename)[0] or
                    'application/octet-stream'
                )
            self.files.append((fieldname, filename, mimetype, body))
            return

        @staticmethod
        def _form_data(name):
            return ('Content-Disposition: form-data; '
                    'name="{}"\r\n').format(name).encode('utf-8')

        @staticmethod
        def _attached_file(name, filename):
            return ('Content-Disposition: file; '
                    'name="{}"; filename="{}"\r\n').format(
                        name, filename).encode('utf-8')

        @staticmethod
        def _content_type(ct):
            return 'Content-Type: {}\r\n'.format(ct).encode('utf-8')

        def __bytes__(self):
            """Return a byte-string representing the form data,
            including attached files.
            """
            buffer = io.BytesIO()
            boundary = b'--' + self.boundary + b'\r\n'

            # Add the form fields
            for name, value in self.form_fields:
                buffer.write(boundary)
                buffer.write(self._form_data(name))
                buffer.write(b'\r\n')
                buffer.write(value.encode('utf-8'))
                buffer.write(b'\r\n')

            # Add the files to upload
            for f_name, filename, f_content_type, body in self.files:
                buffer.write(boundary)
                buffer.write(self._attached_file(f_name, filename))
                buffer.write(self._content_type(f_content_type))
                buffer.write(b'\r\n')
                buffer.write(body)
                buffer.write(b'\r\n')

            buffer.write(b'--' + self.boundary + b'--\r\n')
            return buffer.getvalue()

    bb.debug(2, f"Loading final SBOM: {sbom_path}")
    sbom = Path(sbom_path).read_text()

    form = MultiPartForm()
    form.add_field("project", dt_project)
    form.add_field("bom", sbom)
    payload = bytes(form)
    bb.debug(2, f"Uploading SBOM to project {dt_project} at {dt_sbom_url}")

    req = urllib.request.Request(
        dt_sbom_url,
        data=payload,
        headers={
            "X-API-Key": d.getVar("DEPENDENCYTRACK_API_KEY"),
            "Content-Type": form.get_content_type(),
            "Content-Length": len(payload)
        },
        method="POST")

    try:
      res = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
      bb.error(f"Failed to upload SBOM for project {dt_project} to Dependency Track server at {dt_sbom_url}. [HTTP Error] {e.code}; Reason: {e.reason}")
    token = json.load(res)['token']
    bb.debug(2, "Waiting for SBOM to be processed")

    req = urllib.request.Request(
    f"{dt_sbom_url}/token/{token}",
    headers={ "X-API-Key": d.getVar("DEPENDENCYTRACK_API_KEY") },
    method="GET")

    timeout = 0
    while True:
        try:
          res = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
          bb.error(f"Failed to check for SBOM processing status. [HTTP Error] {e.code}; Reason: {e.reason}")
        if json.load(res)['processing'] is False:
            break
        elif timeout > int(d.getVar("DEPENDENCYTRACK_SBOM_PROCESSING_TIMEOUT")):
            raise Exception('Timeout reached while processing SBOM')
        timeout += 5
        time.sleep(5)

    bb.debug(2, f"Loading final patched CVEs VEX: {vex_path}")
    vex = Path(vex_path).read_text()

    form = MultiPartForm()
    form.add_field("project", dt_project)
    form.add_field("vex", vex)
    payload = bytes(form)

    bb.debug(2, f"Uploading patched CVEs VEX to project {dt_project} at {dt_vex_url}")
    req = urllib.request.Request(
        dt_vex_url,
        data=payload,
        headers={
            "X-API-Key": d.getVar("DEPENDENCYTRACK_API_KEY"),
            "Content-Type": form.get_content_type(),
            "Content-Length": len(payload)
        },
        method="POST")

    try:
      urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
      bb.error(f"Failed to upload VEX for project {dt_project} to Dependency Track server at {dt_vex_url}. [HTTP Error] {e.code}; Reason: {e.reason}")
}

addhandler do_dependencytrack_upload
do_dependencytrack_upload[eventmask] = "bb.event.BuildCompleted"

def read_json(path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())

def write_json(path, content):
    import json
    from pathlib import Path
    Path(path).write_text(json.dumps(content, indent=2))

def get_licenses(d) :
    from pathlib import Path
    import json
    license_expression = d.getVar("LICENSE")
    if license_expression:
        license_json = []
        licenses = license_expression.replace("|", "").replace("&", "").split()
        for license in licenses:
            license_conversion_map = json.loads(d.getVar('DT_LICENSE_CONVERSION_MAP'))
            converted_license = None
            try:
                converted_license =  license_conversion_map[license]
            except Exception as e:
                    pass
            if not converted_license:
                converted_license = license
            # Search for the license in COMMON_LICENSE_DIR and LICENSE_PATH
            for directory in [d.getVar('COMMON_LICENSE_DIR')] + (d.getVar('LICENSE_PATH') or '').split():
                try:
                    with (Path(directory) / converted_license).open(errors="replace") as f:
                        extractedText = f.read()
                        license_data = {
                            "license": {
                                "name" : converted_license,
                                "text": {
                                    "contentType": "text/plain",
                                    "content": extractedText
                                    }
                            }
                        }
                        license_json.append(license_data)
                        break
                except FileNotFoundError:
                    pass
            license_json.append({"expression" : license_expression})
        return license_json 
    return None

import frappe
from frappe import _
from frappe.core.doctype.file.file import File

class CustomFile(File):
    def validate_file_url(self):
        if self.is_remote_file or not self.file_url:
            return

        if not self.file_url.startswith(("/files/", "/private/files/", "/api/method/frappe_s3_attachment.controller.generate_file")):
            # Probably an invalid URL since it doesn't start with http either
            frappe.throw(
                    _("URL must start with http:// or https://"),
                title=_("Invalid URL"),
            )

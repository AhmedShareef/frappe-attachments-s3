from __future__ import unicode_literals

import datetime
import os
import random
import re
import string

import boto3

from botocore.client import Config
from botocore.exceptions import ClientError

import frappe


import magic


class S3Operations(object):

    def __init__(self):
        """
        Function to initialise the aws settings from frappe S3 File attachment
        doctype.
        """
        self.s3_settings_doc = frappe.get_single('S3 File Attachment')

        if (
            self.s3_settings_doc.private_aws_key and
            self.s3_settings_doc.private_aws_secret
        ):
            self.S3_PRIVATE_CLIENT = boto3.client(
                's3',
                aws_access_key_id=self.s3_settings_doc.private_aws_key,
                aws_secret_access_key=self.s3_settings_doc.private_aws_secret,
                region_name=self.s3_settings_doc.private_region_name,
                config=Config(signature_version='s3v4'),
                endpoint_url=self.s3_settings_doc.private_endpoint_url
            )
        else:
            self.S3_PRIVATE_CLIENT = boto3.client(
                's3',
                region_name=self.s3_settings_doc.region_name,
                config=Config(signature_version='s3v4'),
                endpoint_url=self.s3_settings_doc.private_endpoint_url
            )

        self.PRIVATE_BUCKET = self.s3_settings_doc.private_bucket_name
        self.private_folder_name = self.s3_settings_doc.private_folder_name

        if not self.s3_settings_doc.no_separate_public_bucket:
            if (
                self.s3_settings_doc.public_aws_key and
                self.s3_settings_doc.public_aws_secret
            ):
                self.S3_PUBLIC_CLIENT = boto3.client(
                    's3',
                    aws_access_key_id=self.s3_settings_doc.public_aws_key,
                    aws_secret_access_key=self.s3_settings_doc.public_aws_secret,
                    region_name=self.s3_settings_doc.public_region_name,
                    config=Config(signature_version='s3v4'),
                    endpoint_url=self.s3_settings_doc.public_endpoint_url
                )
            else:
                self.S3_PUBLIC_CLIENT = boto3.client(
                    's3',
                    region_name=self.s3_settings_doc.region_name,
                    config=Config(signature_version='s3v4'),
                    endpoint_url=self.s3_settings_doc.public_endpoint_url
                )

            self.PUBLIC_BUCKET = self.s3_settings_doc.public_bucket_name
            self.public_folder_name = self.s3_settings_doc.public_folder_name

        else:
            self.S3_PUBLIC_CLIENT = self.S3_PRIVATE_CLIENT
            self.PUBLIC_BUCKET = self.PRIVATE_BUCKET
            self.public_folder_name = self.private_folder_name

    def strip_special_chars(self, file_name):
        """
        Strips file charachters which doesnt match the regex.
        """
        regex = re.compile('[^0-9a-zA-Z._-]')
        file_name = regex.sub('', file_name)
        return file_name

    def key_generator(self, file_name, parent_doctype, parent_name, is_private):
        """
        Generate keys for s3 objects uploaded with file name attached.
        """

        hook_cmd = frappe.get_hooks().get("s3_key_generator")
        if hook_cmd:
            try:
                k = frappe.get_attr(hook_cmd[0])(
                    file_name=file_name,
                    parent_doctype=parent_doctype,
                    parent_name=parent_name
                )
                if k:
                    return k.rstrip('/').lstrip('/')
            except:
                pass

        file_name = file_name.replace(' ', '_')
        file_name = self.strip_special_chars(file_name)
        key = ''.join(
            random.choice(
                string.ascii_uppercase + string.digits) for _ in range(8)
        )

        today = datetime.datetime.now()
        year = today.strftime("%Y")
        month = today.strftime("%m")
        day = today.strftime("%d")

        doc_path = None

        folder_name = (self.private_folder_name if is_private else self.public_folder_name) or ""
        parent_doctype = parent_doctype or "Common"

        if not doc_path:
            if folder_name:
                final_key = folder_name + "/" + year + "/" + month + \
                    "/" + day + "/" + parent_doctype + "/" + key + "_" + \
                    file_name
            else:
                final_key = year + "/" + month + "/" + day + "/" + \
                    parent_doctype + "/" + key + "_" + file_name
            return final_key
        else:
            final_key = doc_path + '/' + key + "_" + file_name
            return final_key

    def upload_files_to_s3_with_key(
            self, file_path, file_name, is_private, parent_doctype, parent_name
    ):
        """
        Uploads a new file to S3.
        Strips the file extension to set the content_type in metadata.
        """
        mime_type = magic.from_file(file_path, mime=True)
        key = self.key_generator(file_name, parent_doctype, parent_name, is_private)
        content_type = mime_type
        try:
            if is_private:
                self.S3_PRIVATE_CLIENT.upload_file(
                    file_path, self.PRIVATE_BUCKET, key,
                    ExtraArgs={
                        "ContentType": content_type,
                        "Metadata": {
                            "ContentType": content_type,
                            "file_name": file_name
                        }
                    }
                )
            else:
                self.S3_PUBLIC_CLIENT.upload_file(
                    file_path, self.PUBLIC_BUCKET, key,
                    ExtraArgs={
                        "ContentType": content_type,
                        "ACL": 'public-read',
                        "Metadata": {
                            "ContentType": content_type,

                        }
                    }
                )

        except boto3.exceptions.S3UploadFailedError:
            frappe.throw(frappe._("File Upload Failed. Please try again."))
        return key

    def delete_from_s3(self, key):
        """ Delete file from s3"""

        if self.s3_settings_doc.delete_file_from_cloud:

            is_private = frappe.db.get_value("File", { "content_hash": key }, "is_private")

            try:
                if is_private:
                    self.S3_PRIVATE_CLIENT.delete_object(
                        Bucket=self.s3_settings_doc.private_bucket_name,
                        Key=key
                    )
                else:
                    self.S3_PUBLIC_CLIENT.delete_object(
                        Bucket=self.s3_settings_doc.public_bucket_name,
                        Key=key
                    )

            except ClientError:
                frappe.throw(frappe._("Access denied: Could not delete file"))

    def read_file_from_s3(self, key):
        """
        Function to read file from a s3 file.
        """
        is_private = frappe.db.get_value("File", { "content_hash": key }, "is_private")

        if is_private:
            client = self.S3_PRIVATE_CLIENT
            bucket = self.PRIVATE_BUCKET

        else:
            client = self.S3_PUBLIC_CLIENT
            bucket = self.PUBLIC_BUCKET

        return client.get_object(Bucket=bucket, Key=key)

    def get_url(self, key, file_name=None):
        """
        Return url.

        :param bucket: s3 bucket name
        :param key: s3 object key
        """

        is_private = frappe.db.get_value("File", { "content_hash": key }, "is_private")

        if is_private:
            if self.s3_settings_doc.private_signed_url_expiry_time:
                signed_url_expiry_time = self.s3_settings_doc.private_signed_url_expiry_time # noqa
            else:
                signed_url_expiry_time = 120

            client = self.S3_PRIVATE_CLIENT
            bucket = self.PRIVATE_BUCKET

        else:
            if self.s3_settings_doc.public_signed_url_expiry_time:
                signed_url_expiry_time = self.s3_settings_doc.public_signed_url_expiry_time
            else:
                signed_url_expiry_time = 120

            client = self.S3_PUBLIC_CLIENT
            bucket = self.PUBLIC_BUCKET

        params = {
            'Bucket': bucket,
            'Key': key,
        }

        if file_name:
            params['ResponseContentDisposition'] = 'filename={}'.format(file_name)

        url = client.generate_presigned_url(
            'get_object',
            Params=params,
            ExpiresIn=signed_url_expiry_time,
        )

        return url


@frappe.whitelist()
def file_upload_to_s3(doc, method):
    """
    check and upload files to s3. the path check and
    """
    s3_upload = S3Operations()
    path = doc.file_url
    site_path = frappe.utils.get_site_path()
    parent_doctype = doc.attached_to_doctype or 'File'
    parent_name = doc.attached_to_name
    ignore_s3_upload_for_doctype = frappe.local.conf.get('ignore_s3_upload_for_doctype') or ['Data Import']
    if parent_doctype not in ignore_s3_upload_for_doctype:
        if not doc.is_private:
            file_path = site_path + '/public' + path
        else:
            file_path = site_path + path

        key = s3_upload.upload_files_to_s3_with_key(
            file_path, doc.file_name,
            doc.is_private, parent_doctype,
            parent_name
        )

        if doc.is_private:
            method = "frappe_s3_attachment.controller.generate_file"
            file_url = """/api/method/{0}?key={1}&file_name={2}""".format(method, key, doc.file_name)
        else:
            if s3_upload.s3_settings_doc.public_proxy_url:
                file_url = '{}/{}'.format(
                    s3_upload.s3_settings_doc.public_proxy_url,
                    key
                )
            else:
                file_url = '{}/{}/{}'.format(
                    s3_upload.S3_PUBLIC_CLIENT.meta.endpoint_url,
                    s3_upload.PUBLIC_BUCKET,
                    key
                )

        os.remove(file_path)
        frappe.db.sql("""UPDATE `tabFile` SET file_url=%s, folder=%s,
            old_parent=%s, content_hash=%s WHERE name=%s""", (
            file_url, 'Home/Attachments', 'Home/Attachments', key, doc.name))

        doc.file_url = file_url

        if parent_doctype and frappe.get_meta(parent_doctype).get('image_field'):
            frappe.db.set_value(parent_doctype, parent_name, frappe.get_meta(parent_doctype).get('image_field'), file_url)

        frappe.db.commit()


@frappe.whitelist()
def generate_file(key=None, file_name=None):
    """
    Function to stream file from s3.
    """
    if key:
        s3_upload = S3Operations()
        signed_url = s3_upload.get_url(key, file_name)
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = signed_url
    else:
        frappe.local.response['body'] = "Key not found."
    return


def upload_existing_files_s3(name):
    """
    Function to upload all existing files.
    """
    file_doc_name = frappe.db.get_value('File', {'name': name})
    if file_doc_name:
        doc = frappe.get_doc('File', name)
        s3_upload = S3Operations()
        path = doc.file_url
        site_path = frappe.utils.get_site_path()
        parent_doctype = doc.attached_to_doctype
        parent_name = doc.attached_to_name
        if not doc.is_private:
            file_path = site_path + '/public' + path
        else:
            file_path = site_path + path

        # File exists?
        if not os.path.exists(file_path):
            return

        key = s3_upload.upload_files_to_s3_with_key(
            file_path, doc.file_name,
            doc.is_private, parent_doctype,
            parent_name
        )

        if doc.is_private:
            method = "frappe_s3_attachment.controller.generate_file"
            file_url = """/api/method/{0}?key={1}""".format(method, key)
        else:
            file_url = '{}/{}/{}'.format(
                s3_upload.S3_PUBLIC_CLIENT.meta.endpoint_url,
                s3_upload.PUBLIC_BUCKET,
                key
            )

        # Remove file from local.
        os.remove(file_path)

        frappe.db.sql(
            """UPDATE `tabFile` SET file_url=%s, folder=%s,
            old_parent=%s, content_hash=%s WHERE name=%s""",
            (file_url, "Home/Attachments", "Home/Attachments", key, doc.name),
        )
        frappe.db.commit()


def s3_file_regex_match(file_url):
    """
    Match the public file regex match.
    """
    return re.match(
        r'^(https:|/api/method/frappe_s3_attachment.controller.generate_file)',
        file_url
    )


@frappe.whitelist()
def migrate_existing_files():
    if not frappe.db.exists('RQ Job', { 'job_name': 'migrate_existing_files', 'status': ['not in', ['failed', 'finished']] }):
        frappe.enqueue(_migrate_existing_files, queue='long', job_name='migrate_existing_files')
    return True

def _migrate_existing_files():
    """
    Function to migrate the existing files to s3.
    """

    files_list = frappe.get_all(
        'File',
        fields=['name', 'file_url']
    )
    for file in files_list:
        if file['file_url']:
            if not s3_file_regex_match(file['file_url']):
                upload_existing_files_s3(file['name'])
    return True

def delete_from_cloud(doc, method):
    """Delete file from s3"""
    s3 = S3Operations()
    s3.delete_from_s3(doc.content_hash)


@frappe.whitelist()
def ping():
    """
    Test function to check if api function work.
    """
    return "pong"
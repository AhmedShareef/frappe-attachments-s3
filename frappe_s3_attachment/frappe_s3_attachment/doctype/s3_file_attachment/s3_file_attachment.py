# -*- coding: utf-8 -*-
# Copyright (c) 2018, Frappe and contributors
# For license information, please see license.txt

from __future__ import unicode_literals
import frappe
from frappe.model.document import Document

class S3FileAttachment(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		delete_file_from_cloud: DF.Check
		no_separate_public_bucket: DF.Check
		private_aws_key: DF.Data | None
		private_aws_secret: DF.Data | None
		private_bucket_name: DF.Data | None
		private_endpoint_url: DF.Data | None
		private_folder_name: DF.Data | None
		private_region_name: DF.Data | None
		private_signed_url_expiry_time: DF.Int
		public_aws_key: DF.Data | None
		public_aws_secret: DF.Data | None
		public_bucket_name: DF.Data | None
		public_endpoint_url: DF.Data | None
		public_folder_name: DF.Data | None
		public_proxy_url: DF.Data | None
		public_region_name: DF.Data | None
		public_signed_url_expiry_time: DF.Int
	# end: auto-generated types
	pass

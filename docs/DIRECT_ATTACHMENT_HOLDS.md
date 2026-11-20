# Direct attachment holds

Direct-chat attachments are personal records. A designated compliance administrator assigns a verified staff account to an exact attachment after verifying a valid legal authority or approved case reference. Use the private `sectalk_private.st_v6_direct_file_hold_scope` table to record the staff account UUID, attachment UUID, and authorization reference. Keep case contents and personal details out of the reference.

Staff enter Safety → Attachment holds after authenticator verification. An assignment authorizes retention actions on its recorded attachment, and staff can review and release holds they personally placed. Holds from different assigned staff can overlap. Removing an assignment ends the operator’s access and leaves existing holds active. A compliance administrator must arrange a supported release before deprovisioning the placing account.

Ordinary download, preview and share rules remain in force. Attachment deletion withdraws ordinary access immediately. The purge job checks every active formal hold and explicitly shared report evidence before removing bytes. Hold placement uses the same attachment-row lock and declines an existing purge lease or missing Storage object.

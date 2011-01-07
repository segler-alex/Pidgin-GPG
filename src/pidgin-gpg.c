/*                
 * Pidgin - GPG Pidgin Plugin
 *                                
 * Copyright (C) 2010, Aerol <rectifier04@gmail.com>
 *                     segler_alex <segler_alex@web.de>
 *                                                                 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or   
 * (at your option) any later version.                                 
 *                                                                     
 * This program is distributed in the hope that it will be useful,     
 * but WITHOUT ANY WARRANTY; without even the implied warranty of      
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the       
 * GNU General Public License for more details.                        
 *                                                                     
 * You should have received a copy of the GNU General Public License   
 * along with this program; if not, write to the Free Software         
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *                                                                               
 */

#define PURPLE_PLUGINS

#define PLUGIN_ID "gtk-aerol-pidgin-gpg"
#define PREF_ROOT "/plugins/core/gtk-aerol-pidgin-gpg"
#define PREF_MY_KEY "/plugins/core/gtk-aerol-pidgin-gpg/my_key_fpr"

#include <glib.h>
#include <locale.h>
#include <string.h>

#include "notify.h"
#include "plugin.h"
#include "version.h"

#include <pluginpref.h>
#include <prefs.h>
#include <debug.h>

#include <gpgme.h>

/* ------------------
 * xmlnode.h lacks a method for clearing the data of a node
 * ------------------ */
void
xmlnode_clear_data(xmlnode *node)
{
	xmlnode *data_node, *sibling = NULL;

	g_return_if_fail(node != NULL);

	data_node = node->child;
	while (data_node) {
		if(data_node->type == XMLNODE_TYPE_DATA)
		{
			if (node->lastchild == data_node) {
				node->lastchild = sibling;
			}
			if (sibling == NULL) {
				node->child = data_node->next;
				xmlnode_free(data_node);
				data_node = node->child;
			} else {
				sibling->next = data_node->next;
				xmlnode_free(data_node);
				data_node = sibling->next;
			}
		}else{
			sibling = data_node;
			data_node = data_node->next;
		}
	}
}

/* ------------------
 * armor a string
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* str_armor(const char* unarmored)
{
	char* header = "-----BEGIN PGP SIGNATURE-----\n\n";
	char* footer = "\n-----END PGP SIGNATURE-----";

	char* buffer = malloc(strlen(header)+strlen(footer)+strlen(unarmored)+1);
	strcpy(buffer, header);
	strcat(buffer, unarmored);
	strcat(buffer, footer);
	return buffer;
}

/* ------------------
 * sign a plain string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* sign(const char* plain_str,const char* fpr)
{
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_key_t key;
	gpgme_data_t plain,sig;
	const int MAX_LEN = 10000;
	char *sig_str = NULL;
	char *sig_str_dup = NULL;
	size_t len = 0;

	// connect to gpgme
	gpgme_check_version (NULL);
	error = gpgme_new(&ctx);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_new failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		return NULL;
	}

	// get key by fingerprint
	error = gpgme_get_key(ctx,fpr,&key,1);
	if (error || !key)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_get_key failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		gpgme_release (ctx);
		return NULL;
	}

	// select signers
	gpgme_signers_clear(ctx);
	error = gpgme_signers_add (ctx,key);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_signers_add failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		gpgme_release (ctx);
		return NULL;
	}

	// create data containers
	gpgme_data_new_from_mem (&plain, plain_str,strlen(plain_str),1);
	gpgme_data_new(&sig);

	// sign message, ascii armored
	gpgme_set_armor(ctx,1);
	error = gpgme_op_sign(ctx,plain,sig,GPGME_SIG_MODE_DETACH);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_op_sign failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		gpgme_release (ctx);
		return NULL;
	}

	// release memory for data containers
	gpgme_data_release(plain);
	sig_str = gpgme_data_release_and_get_mem(sig,&len);
	if (sig_str != NULL)
	{
		sig_str[len] = 0;
		sig_str_dup = strdup(plain_str);
	}
	gpgme_free(sig_str);
	
	// close gpgme connection
	gpgme_release (ctx);

	return sig_str_dup;
}

/* ------------------
 * verify a signed string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE!
 * ------------------ */
static char* verify(const char* sig_str)
{
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_data_t plain,sig,sig_text;
	gpgme_verify_result_t result;
	char* fpr = NULL;
	char* armored_sig_str = NULL;

	if (sig_str == NULL)
	{
		purple_debug_error(PLUGIN_ID,"verify got null parameter\n");
		return NULL;
	}

	// connect to gpgme
	gpgme_check_version (NULL);
	error = gpgme_new(&ctx);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_new failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		return NULL;
	}

	// armor sig_str
	armored_sig_str = str_armor(sig_str);

	// create data containers
	gpgme_data_new_from_mem (&sig, armored_sig_str,strlen(armored_sig_str),1);
	gpgme_data_new(&plain);

	// try to verify
	error = gpgme_op_verify(ctx,sig,NULL,plain);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_op_verify failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		gpgme_release (ctx);
		return NULL;
	}

	// get result
 	result = gpgme_op_verify_result (ctx);
	if (result != NULL)
	{
		if (result->signatures != NULL)
		{
			// return the fingerprint of the key that made the signature
			fpr = strdup(result->signatures->fpr);
		}
	}

	// release memory for data containers
	gpgme_data_release(sig);
	gpgme_data_release(plain);

	return fpr;
}

/* ------------------
 * encrypt a plain string with the key found with fingerprint fpr
 * ------------------ */
static char* encrypt(const char* plain_str, const char* fpr)
{
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_key_t key;
	gpgme_data_t plain,cipher;
	const int MAX_LEN = 10000;
	char sig_str[MAX_LEN];
	int len = 0;

	// connect to gpgme
	gpgme_check_version (NULL);
	error = gpgme_new(&ctx);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_new failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		return NULL;
	}

	// get key by fingerprint
	error = gpgme_get_key(ctx,fpr,&key,1);
	if (error || !key)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_get_key failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		gpgme_release (ctx);
		return NULL;
	}

	// close gpgme connection
	gpgme_release (ctx);

	return NULL;
}

/* ------------------
 * decrypt a plain string with the key found with fingerprint fpr
 * FREE MEMORY AFTER USAGE OF RETURN VALUE
 * ------------------ */
static char* decrypt(char* cipher_str)
{
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_data_t plain,cipher;
	size_t len = 0;
	char* plain_str = NULL;
	char* plain_str_dup = NULL;
	char* armored_buffer;

	// add header and footer:
	armored_buffer = str_armor(cipher_str);

	// connect to gpgme
	gpgme_check_version (NULL);
	error = gpgme_new(&ctx);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_new failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		return NULL;
	}

	// create data containers
	gpgme_data_new_from_mem (&cipher, armored_buffer,strlen(armored_buffer),1);
	gpgme_data_new(&plain);

	// decrypt
	error = gpgme_op_decrypt(ctx,cipher,plain);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_op_decrypt failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		gpgme_release (ctx);
		return NULL;
	}

	// release memory for data containers
	gpgme_data_release(cipher);
	plain_str = gpgme_data_release_and_get_mem(plain,&len);
	if (plain_str != NULL)
	{
		plain_str[len] = 0;
		plain_str_dup = strdup(plain_str);
	}
	gpgme_free(plain_str);

	// close gpgme connection
	gpgme_release (ctx);

	return plain_str_dup;
}


/* ------------------
 * initialize gpgme lib on module load
 * ------------------ */
static void init_gpgme ()
{
	const char* version;

	/* Initialize the locale environment.  */
	setlocale (LC_ALL, "");
	version = gpgme_check_version (NULL);
	purple_debug_info(PLUGIN_ID,"Found gpgme version: %s\n",version);

	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
	// For W32 portability.
	#ifdef LC_MESSAGES
	gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
	#endif
}

static const char* NS_SIGNED = "jabber:x:signed";
static const char* NS_ENC = "jabber:x:encrypted";

/* ------------------
 * called on received message
 * ------------------ */
static gboolean
jabber_message_received(PurpleConnection *pc, const char *type, const char *id,
                        const char *from, const char *to, xmlnode *message)
{
	const xmlnode* parent_node = message;
	xmlnode* x_node = NULL;

	purple_debug_misc(PLUGIN_ID, "jabber message (type=%s, id=%s, from=%s to=%s) %p\n",
	                  type ? type : "(null)", id ? id : "(null)",
	                  from ? from : "(null)", to ? to : "(null)", message);

	// check if message has special "x" child node => encrypted message
	x_node = xmlnode_get_child_with_namespace(parent_node,"x",NS_ENC);
	if (x_node != NULL)
	{
		purple_debug_info(PLUGIN_ID, "user %s sent us an encrypted message\n",from);

		// get data of "x" node
		char* cipher_str = xmlnode_get_data(x_node);
		if (cipher_str != NULL)
		{
			// try to decrypt
			char* plain_str = decrypt(cipher_str);
			if (plain_str != NULL)
			{
				purple_debug_info(PLUGIN_ID, "decrypted message: %s\n",plain_str);
				// find body node
				xmlnode *body_node = xmlnode_get_child(parent_node,"body");
				if (body_node != NULL)
				{
					// clear body node data if it is found
					xmlnode_clear_data(body_node);
				}else
				{
					// add body node if it is not found
					body_node = xmlnode_new_child(message,"body");
				}
				// set "body" content node to decrypted string
				xmlnode_insert_data(body_node,"Encrypted message: ",-1);				
				xmlnode_insert_data(body_node,plain_str,-1);
			}else
			{
				purple_debug_error(PLUGIN_ID, "could not decrypt message!\n");
			}
		}else
		{
			purple_debug_error(PLUGIN_ID, "xml token had no data!\n");
		}
	}

	/* We don't want the plugin to stop processing */
	return FALSE;
}

/* ------------------
 * called on received presence
 * ------------------ */
static gboolean
jabber_presence_received(PurpleConnection *pc, const char *type,
                         const char *from, xmlnode *presence)
{
	const xmlnode* parent_node = presence;
	xmlnode* x_node = NULL;

	// check if presence has special "x" childnode
	x_node = xmlnode_get_child_with_namespace(parent_node,"x",NS_SIGNED);
	if (x_node != NULL)
	{
		// user supports openpgp encryption
		purple_debug_info(PLUGIN_ID, "user %s supports openpgp encryption!\n",from);

		char* x_node_data = xmlnode_get_data(x_node);
		if (x_node_data != NULL)
		{
			// try to verify
			char* fpr = verify(x_node_data);
			if (fpr != NULL)
			{
				purple_debug_info(PLUGIN_ID, "user %s has fingerprint %s\n",from,fpr);
			}else
			{
				purple_debug_error(PLUGIN_ID, "could not verify presence of user %s\n",from);
			}
		}else
		{
			purple_debug_info(PLUGIN_ID, "user %s sent empty signed presence\n",from);
		}
	}

	/* We don't want the plugin to stop processing */
	return FALSE;
}

/* ------------------
 * called on every sent packet
 * ------------------ */
void jabber_send_signal_cb(PurpleConnection *pc, xmlnode **packet,
                           gpointer unused)
{
	if (NULL == packet)
		return;

	g_return_if_fail(PURPLE_CONNECTION_IS_VALID(pc));

	// check if user selected a main key
	const char* fpr = purple_prefs_get_string(PREF_MY_KEY);
	if (fpr == NULL)
		fpr = "";
	if (strcmp(fpr,"") != 0)
	{// user did select a key
		// try to sign a string
		
		// if we are sending a presence stanza, add new child node
		//  so others know we support openpgp
		if (g_str_equal((*packet)->name, "presence"))
		{
			const char* status_str = NULL;
			xmlnode* status_node;

			//TODO: does not work
			// get status message from packet
			status_node = xmlnode_get_child(*packet,"status");
			if (status_node != NULL)
			{
				status_str = xmlnode_get_data(status_node);
			}

			// sign status message
			if (status_str == NULL)
				status_str = "";
			purple_debug_misc(PLUGIN_ID, "signing status '%s' with key %s\n",status_str,fpr);

			char* sig_str = sign(status_str,fpr);
			if (sig_str == NULL)
			{
				purple_debug_error(PLUGIN_ID,"sign failed\n");
				return;
			}

			// create special "x" childnode
			purple_debug_misc(PLUGIN_ID, "sending presence with signature\n");
			xmlnode *x_node = xmlnode_new_child(*packet,"x");
			xmlnode_set_namespace(x_node, NS_SIGNED);
			xmlnode_insert_data(x_node, sig_str,-1);
		}else
		if (g_str_equal((*packet)->name, "message"))
		{
			xmlnode* body_node = xmlnode_get_child(*packet,"body");
			if (body_node != NULL)
			{
				// get message
				char* message = strdup(xmlnode_get_data(body_node));
				char* enc_str = NULL;

				// encrypt message
				//TODO: get public key fpr from receiver
				enc_str = encrypt(message,fpr);
				if (enc_str != NULL)
				{
					// remove message from body
					xmlnode_clear_data(body_node);
					xmlnode_insert_data(body_node,"[ERROR: This message is encrypted, and you are unable to decrypt it.]",-1);

					// add special "x" childnode for encrypted text
					purple_debug_misc(PLUGIN_ID, "sending encrypted message\n");
					xmlnode *x_node = xmlnode_new_child(*packet,"x");
					xmlnode_set_namespace(x_node, NS_ENC);
					xmlnode_insert_data(x_node, enc_str,-1);
				}else
				{
					purple_debug_error(PLUGIN_ID, "could not encrypt message\n");
				}
			}
		}
	}else
	{
		purple_debug_misc(PLUGIN_ID, "no key selecteded!\n");
	}
}

/* ------------------
 * called on module load
 * ------------------ */
static gboolean plugin_load(PurplePlugin *plugin)
{
	// register presence receiver handler
	void *jabber_handle   = purple_plugins_find_with_id("prpl-jabber");

	if (jabber_handle)
	{
		purple_signal_connect(jabber_handle, "jabber-receiving-message", plugin,PURPLE_CALLBACK(jabber_message_received), NULL);
		purple_signal_connect(jabber_handle, "jabber-receiving-presence", plugin,PURPLE_CALLBACK(jabber_presence_received), NULL);
		purple_signal_connect(jabber_handle, "jabber-sending-xmlnode", plugin, PURPLE_CALLBACK(jabber_send_signal_cb), NULL);
	}

	/*
	Initialize everything needed; get the passphrase for encrypting and decrypting messages.
	Attach to all windows the chat windows.
	*/
/*	attach_to_all_windows();
	purple_signal_connect(pidgin_conversations_get_handle(), "conversation-displayed", plugin, PURPLE_CALLBACK(conv_created), NULL);
	purple_signal_connect(purple_conversations_get_handle(), "conversation-extended-menu", plugin, PURPLE_CALLBACK(conv_menu_cb), NULL);*/

	// initialize gpgme lib on module load
	init_gpgme();


	return TRUE;
}

/*static gboolean plugin_unload(PurplePlugin *plugin) {
	detach_from_all_windows();
	return TRUE;
}*/

/* ------------------
 * preferences dialog function
 * ------------------ */
static PurplePluginPrefFrame *
get_plugin_pref_frame(PurplePlugin *plugin) {
	PurplePluginPrefFrame *frame;
	PurplePluginPref *ppref;
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_key_t key;

	// create preferences frame
	frame = purple_plugin_pref_frame_new();
	
	// connect to gpgme
	gpgme_check_version (NULL);
	error = gpgme_new(&ctx);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_new failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		return NULL;
	}

	// create key chooser preference
	ppref = purple_plugin_pref_new_with_name_and_label(PREF_MY_KEY,"My key");
	purple_plugin_pref_set_type(ppref, PURPLE_PLUGIN_PREF_CHOICE);
	purple_plugin_pref_add_choice(ppref, "None", "");

	// list keys (secret keys)
	error = gpgme_op_keylist_start (ctx,NULL,1);
	if (error == GPG_ERR_NO_ERROR)
	{
		while (!error)
		{
			error = gpgme_op_keylist_next (ctx, &key);
			if (error) break;
			// add key to preference chooser
			//TODO: find something better for strdup, or some possibility to free memory after preferences dialog closed
			purple_plugin_pref_add_choice(ppref, strdup(key->uids->uid), strdup(key->subkeys->fpr));
			purple_debug_info(PLUGIN_ID,"Found secret key for: %s has fpr %s\n",key->uids->uid,key->subkeys->fpr);
			gpgme_key_release (key);
		}
	}else
	{
		purple_debug_error(PLUGIN_ID,"gpgme_op_keylist_start failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
	}
	// close gpgme connection
	gpgme_release (ctx);

	purple_plugin_pref_frame_add(frame, ppref);

	return frame;
}

/* ------------------
 * The plugin ui info struct for preferences dialog
 * ------------------ */
static PurplePluginUiInfo prefs_info = {
	get_plugin_pref_frame,
	0,   /* page_num (Reserved) */
	NULL, /* frame (Reserved) */
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

/* ------------------
 * The plugin info struct
 * ------------------ */
static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    PLUGIN_ID,
    "Pidgin GPG",
    "0.1",

    "GPG Plugin for Pidgin",          
    "Simple GPG Plugin for Pidgin.",          
    "Aerol <rectifier04@gmail.com>",                          
    "https://github.com/Aerol/Pidgin-GPG",     
    
    plugin_load,                   
    NULL,                          
    NULL,                          
                                   
    NULL,                          
    NULL,                          
    &prefs_info,                        
    NULL,                   
    NULL,                          
    NULL,                          
    NULL,                          
    NULL                           
};                               

/* ------------------
 * plugin init
 * ------------------ */
static void init_plugin(PurplePlugin *plugin)
{
	// create entries in prefs if they are not there
	purple_prefs_add_none(PREF_ROOT);
	purple_prefs_add_string(PREF_MY_KEY, "");
}

PURPLE_INIT_PLUGIN(pidgin-gpg, init_plugin, info)

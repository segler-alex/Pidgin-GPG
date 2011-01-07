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
 * sign a plain string with the key found with fingerprint fpr
 * ------------------ */
static char* sign(const char* plain_str,const char* fpr)
{
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_key_t key;
	gpgme_data_t plain,sig;
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
		return NULL;
	}

	// select signers
	gpgme_signers_clear(ctx);
	error = gpgme_signers_add (ctx,key);
	if (error)
	{
		purple_debug_error(PLUGIN_ID,"gpgme_signers_add failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
		return NULL;
	}

	// create data containers
	gpgme_data_new_from_mem (&plain, plain_str,strlen(plain_str),1);
	gpgme_data_new(&sig);

	// sign message, ascii armored
	gpgme_set_armor(ctx,1);
	gpgme_op_sign(ctx,plain,sig,GPGME_SIG_MODE_DETACH);

	// read data from output container into sig_str buffer
	gpgme_data_rewind(sig);
	len = gpgme_data_read(sig,sig_str,MAX_LEN);
	sig_str[len] = 0;

	// release memory for data containers
	gpgme_data_release(sig);
	gpgme_data_release(plain);
	
	// close gpgme connection
	gpgme_release (ctx);

	return strdup(sig_str);
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

/* ------------------
 * called on received message
 * ------------------ */
static gboolean
jabber_message_received(PurpleConnection *pc, const char *type, const char *id,
                        const char *from, const char *to, xmlnode *message)
{
	purple_debug_misc(PLUGIN_ID, "jabber message (type=%s, id=%s, "
	                  "from=%s to=%s) %p\n",
	                  type ? type : "(null)", id ? id : "(null)",
	                  from ? from : "(null)", to ? to : "(null)", message);

	/* We don't want the plugin to stop processing */
	return FALSE;
}

static const char* NS_SIGNED = "jabber:x:signed";

/* ------------------
 * called on received presence
 * ------------------ */
static gboolean
jabber_presence_received(PurpleConnection *pc, const char *type,
                         const char *from, xmlnode *presence)
{
	const xmlnode* parent_node = presence;
	xmlnode* x_node = NULL;

	purple_debug_misc(PLUGIN_ID, "jabber presence received\n");

	// check if presence has special "x" childnode
	x_node = xmlnode_get_child_with_namespace(parent_node,"x",NS_SIGNED);
	if (x_node != NULL)
	{
		// user supports openpgp encryption
		purple_debug_misc(PLUGIN_ID, "user %s supports openpgp encryption!\n",from);
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
			//const xmlnode *parent_node = (const xmlnode*)packet;
			/*status_node = xmlnode_get_child(parent_node,"status");
			if (status_node != NULL)
			{
				status_str = xmlnode_get_data(status_node);
			}*/

			// sign status message
			if (status_str == NULL)
				status_str = "";
			purple_debug_misc(PLUGIN_ID, "signing '%s'\n",status_str);

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

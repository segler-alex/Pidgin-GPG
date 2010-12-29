/*                
 * Pidgin - GPG Pidgin Plugin
 *                                
 * Copyright (C) 2010, Aerol <rectifier04@gmail.com>
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

/* Pidgin Plugin C Documentation at
 *
 * Gpg Documentation:
 * info gpgme

 * The name space of GPGME is `gpgme_*' for function names and data
 * types and `GPGME_*' for other symbols.  Symbols internal to GPGME take
 * the form `_gpgme_*' and `_GPGME_*'.
 *
 * Because GPGME makes use of the GPG Error library, using GPGME will
 * also use the `GPG_ERR_*' name space directly, and the `gpg_err*' and
 * `gpg_str*' name space indirectly.
 */

#include <gpgme.h>

#define PURPLE_PLUGINS

#include <glib.h>
#include <locale.h>

#include "notify.h"
#include "plugin.h"
#include "version.h"

void init_gpgme (void) {
    /* Initialize the locale environment.  */
    setlocale (LC_ALL, "");
    gpgme_check_version (NULL);
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    // For W32 portability.
    #ifdef LC_MESSAGES
        gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    #endif
}

static gboolean plugin_load(PurplePlugin *plugin) {
  /*
  Initialize everything needed; get the passphrase for encrypting and decrypting messages.
  Attach to all windows the chat windows.
  */
  attach_to_all_windows();
  purple_signal_connect(pidgin_conversations_get_handle(), "conversation-displayed", plugin, PURPLE_CALLBACK(conv_created), NULL);
  purple_signal_connect(purple_conversations_get_handle(), "conversation-extended-menu", plugin, PURPLE_CALLBACK(conv_menu_cb), NULL);
  return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin) {
  detach_from_all_windows();
return TRUE
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    PIDGIN_PLUGIN_TYPE,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    "gtk-aerol-pidgin-gpg",
    "Pidgin GPG",
    "0.1",

    "GPG Plugin for Pidgin",          
    "Simple GPG Plugin for Pidgin.",          
    "Aerol <rectifier04@gmail.com>",                          
    "http://thatweirdguy.co.cc",     
    
    plugin_load,                   
    NULL,                          
    NULL,                          
                                   
    NULL,                          
    NULL,                          
    NULL,                        
    NULL,                   
    NULL,                          
    NULL,                          
    NULL,                          
    NULL                           
};                               
    
static void init_plugin(PurplePlugin *plugin)
{                                  
}

PURPLE_INIT_PLUGIN(pidgin-gpg, init_plugin, info)

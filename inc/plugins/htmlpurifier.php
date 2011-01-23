<?php
/**
 * This file is part of HTMLPurifier plugin for MyBB.
 * Copyright (C) 2011 Andreas Klauer <Andreas.Klauer@metamorpher.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
    die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

/* --- Plugin API: --- */

function htmlpurifier_info()
{
    return array(
        "name"          => "HTMLPurifier for MyBB",
        "description"   => "Remove malicious code from HTML in posts. Depends on <a href=\"http://htmlpurifier.org/\"><img src=\"http://htmlpurifier.org/live/art/powered.png\" alt=\"Powered by HTML Purifier\" border=\"0\" /> library</a>.",
        "website"       => "https://github.com/frostschutz/HTMLPurifier-MyBB",
        "author"        => "Andreas Klauer",
        "authorsite"    => "mailto:Andreas.Klauer@metamorpher.de",
        "version"       => "1.0",
        "guid"          => "b27ff3ca01fe7fa37927416e86d48fae",
        "compatibility" => "16*"
        );
}

function htmlpurifier_activate()
{
    @mkdir(MYBB_ROOT.'cache/htmlpurifier');

    if(!@file_exists(MYBB_ROOT.'inc/plugins/htmlpurifier/HTMLPurifier.php')
       || !@file_exists(MYBB_ROOT.'inc/plugins/htmlpurifier/HTMLPurifier.auto.php')
       || !@file_exists(MYBB_ROOT.'inc/plugins/htmlpurifier/HTMLPurifier.func.php'))
    {
        flash_message('The <a href="http://htmlpurifier.org/"><img src="http://htmlpurifier.org/live/art/powered.png" alt="Powered by HTML Purifier" border="0" /> library</a> is missing. Please download it and upload the contents of the <em>library/</em> folder to <em>inc/plugins/htmlpurifier/</em>', 'error');
        admin_redirect('index.php?module=config-plugins');
    }

    if(!@is_writable(MYBB_ROOT.'cache/htmlpurifier/'))
    {
        flash_message('Please create a directory <em>cache/htmlpurifier</em> and make it writable.', 'error');
        admin_redirect('index.php?module=config-plugins');
    }
}

/* --- Hooks: --- */

global $plugins, $settings;

$plugins->add_hook('datahandler_post_validate_thread', 'htmlpurifier_post');
$plugins->add_hook('datahandler_post_validate_post', 'htmlpurifier_post');

if($settings['pmsallowhtml'])
{
    $plugins->add_hook('datahandler_pm_validate', 'htmlpurifier_pm');
}

if($settings['sightml'])
{
    $plugins->add_hook('usercp_do_editsig_start', 'htmlpurifier_sig_ucp');
}

/* --- Functions: --- */

/**
 * Filter HTML when posting.
 */
function htmlpurifier_post($handler)
{
    $fid = $handler->data['fid'];

    $forum = get_forum($fid);

    if($forum['allowhtml'])
    {
        $handler->data['message'] = htmlpurifier_do($handler->data['message'],
                                                    $forum['allowmycode']);
    }
}

/**
 * Filter HTML in PM
 */
function htmlpurifier_pm($handler)
{
    global $settings;

    $handler->data['message'] = htmlpurifier_do($handler->data['message'],
                                                $settings['pmsallowmycode']);
}

/**
 * Filter HTML in Signature
 */
function htmlpurifier_sig_ucp()
{
    global $mybb;

    $mybb->input['signature'] = htmlpurifier_do($mybb->input['signature'],
                                                $settings['sigmycode']);
}

/**
 * Purify HTML.
 */
function htmlpurifier_do($html, $mycode=false)
{
    require_once MYBB_ROOT.'inc/plugins/htmlpurifier/HTMLPurifier.auto.php';
    require_once MYBB_ROOT.'inc/plugins/htmlpurifier/HTMLPurifier.func.php';

    // Special treatment for code tags.
    if($mycode)
    {
        $html = preg_replace_callback("#\[(code|php)\](.*?)\[/\\1\]#si",
                                      create_function('$matches',
                                                      'return htmlspecialchars($matches[0]);'),
                                      $html);
    }

    $config = HTMLPurifier_Config::createDefault();
    $config->set('Cache.SerializerPath', MYBB_ROOT.'cache/htmlpurifier');
    $purifier = new HTMLPurifier($config);
    $html = $purifier->purify($html);

    // Revert special treatment for code tags.
    if($mycode)
    {
        $html = preg_replace_callback("#\[(code|php)\](.*?)\[/\\1\]#si",
                                      create_function('$matches',
                                                      'return htmlspecialchars_decode($matches[0]);'),
                                      $html);
    }

    return $html;
}

/* --- End of file. --- */
?>

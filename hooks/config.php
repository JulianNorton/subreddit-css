<?php
// Don't store this config file in the web root, or at the very least make sure it's not accessible from a web server.
$config = [
    'subreddit_name' => 'web_design',               // The name of the subreddit to sync images and assets with.
    'github' => [
        // The secret for the GitHub webhook, optional, but should be set for verifying that GitHub is the sender of
        // incoming POST requests.
        // @see https://developer.github.com/webhooks/securing/
        'secret' => NULL,
        // All of these values can be changed to NULL to disable the syncing of the resource.
        'stylesheet_path' => 'web_design.css',      // Path to the stylesheet to sync.
        'assets_dir' => 'assets/',                  // Path to the assets folder, containing all images to sync.
        'header_path' => 'assets/logo.png',         // Path to the header, the subreddit logo to sync.
        'icon_mobile_path' => NULL,                 // Path to the mobile icon for the subreddit to sync.
        'header_mobile_path' => NULL                // Path to the subreddit banner/mobile header to sync.
    ],
    // OAUTH configuration for the reddit API.
    // @see https://github.com/reddit/reddit/wiki/OAuth2-Quick-Start-Example
    'oauth' => [
        // All of the following are required.
        'mod_username' => '',     // Username of a moderator of the subreddit to sync.
        'mod_password' => '',     // Password of a moderator of the subreddit to sync.
        'secret' => '',           // Secret of the reddit script, generated/given when registering the script.
        'client_id' => ''         // The ID of the reddit script, generated when registering the script.
    ]
];

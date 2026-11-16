"""Bundled reference descriptions for well-known Android permissions.

``uses-permission`` entries in a manifest carry only a name; the
*protection level* is a parsed manifest fact (see
:mod:`masanalyzer.overview`), but a short human description of what a
platform permission grants comes from the official Android
documentation, not from the APK.  This table ships the concise official
wording for the permissions apps actually declare; anything else stays
without a description rather than being invented.
"""

from __future__ import annotations

from typing import Optional

# name -> concise official-style description of what the permission grants
PERMISSION_DESCRIPTIONS = {
    "android.permission.ACCESS_CHECKIN_PROPERTIES":
        "read/write the device check-in properties database",
    "android.permission.ACCESS_COARSE_LOCATION":
        "approximate device location (coarse, cell/wifi based)",
    "android.permission.ACCESS_FINE_LOCATION":
        "precise device location (GPS and network based)",
    "android.permission.ACCESS_BACKGROUND_LOCATION":
        "access device location while the app is not in use",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS":
        "access extra location provider commands",
    "android.permission.ACCESS_NETWORK_STATE":
        "view the device's network connection state",
    "android.permission.ACCESS_NOTIFICATION_POLICY":
        "read/modify the do-not-disturb notification policy",
    "android.permission.ACCESS_WIFI_STATE":
        "view the device's Wi-Fi connection state",
    "android.permission.ADD_VOICEMAIL":
        "add voicemails into the device's voicemail system",
    "android.permission.BLUETOOTH":
        "pair with and connect to Bluetooth devices",
    "android.permission.BLUETOOTH_ADMIN":
        "discover and pair Bluetooth devices",
    "android.permission.BLUETOOTH_CONNECT":
        "connect to paired Bluetooth devices",
    "android.permission.BLUETOOTH_SCAN":
        "discover and identify nearby Bluetooth devices",
    "android.permission.BODY_SENSORS":
        "access body sensor data (e.g. heart rate)",
    "android.permission.BROADCAST_STICKY":
        "broadcast sticky notifications that remain after delivery",
    "android.permission.CALL_PHONE":
        "directly place phone calls without user confirmation",
    "android.permission.CAMERA":
        "take pictures and record video with the camera",
    "android.permission.CHANGE_NETWORK_STATE":
        "change the device's network connectivity state",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE":
        "allow Wi-Fi multicast reception",
    "android.permission.CHANGE_WIFI_STATE":
        "change the device's Wi-Fi connection state",
    "android.permission.CLEAR_APP_CACHE":
        "delete the cached files of other applications",
    "android.permission.DELETE_CACHE_FILES":
        "delete other applications' cache files",
    "android.permission.DELETE_PACKAGES":
        "uninstall other applications",
    "android.permission.DEVICE_POWER":
        "reboot the device / low-level power control",
    "android.permission.DISABLE_KEYGUARD":
        "disable the device's keylock",
    "android.permission.DUMP":
        "retrieve the system's internal state dump",
    "android.permission.EXPAND_STATUS_BAR":
        "expand/collapse the system status bar",
    "android.permission.FOREGROUND_SERVICE":
        "start foreground services",
    "android.permission.GET_ACCOUNTS":
        "list the accounts known to the device",
    "android.permission.GET_PACKAGE_SIZE":
        "query the storage footprint of installed applications",
    "android.permission.GET_TASKS":
        "list currently running tasks (legacy)",
    "android.permission.GLOBAL_SEARCH":
        "provide content for the system global search",
    "android.permission.INSTALL_PACKAGES":
        "install other applications",
    "android.permission.INSTALL_LOCATION_PROVIDER":
        "install a system location provider",
    "android.permission.INTERNET":
        "full network access (open network sockets)",
    "android.permission.KILL_BACKGROUND_PROCESSES":
        "kill background processes of other applications",
    "android.permission.MANAGE_EXTERNAL_STORAGE":
        "broad access to external storage (all files, all apps' dirs)",
    "android.permission.MANAGE_OWN_CALLS":
        "manage the app's own ongoing calls",
    "android.permission.MASTER_CLEAR":
        "factory reset the device",
    "android.permission.MODIFY_AUDIO_SETTINGS":
        "modify the device's global audio settings",
    "android.permission.MODIFY_PHONE_STATE":
        "modify the telephony state (radio, voicemail, calls)",
    "android.permission.NFC":
        "perform NFC I/O operations",
    "android.permission.PACKAGE_USAGE_STATS":
        "collect component usage statistics",
    "android.permission.PERSISTENT_ACTIVITY":
        "make parts of the app persistent in memory (legacy)",
    "android.permission.POST_NOTIFICATIONS":
        "post notifications",
    "android.permission.PROCESS_OUTGOING_CALLS":
        "intercept outgoing calls and their numbers (legacy)",
    "android.permission.PROCESS_TRANSCRIPT_AUDIO":
        "process assistant audio transcripts",
    "android.permission.QUERY_ALL_PACKAGES":
        "query the full list of installed applications",
    "android.permission.READ_CALENDAR":
        "read the device's calendar events",
    "android.permission.READ_CALL_LOG":
        "read the device's call log",
    "android.permission.READ_CONTACTS":
        "read the device's contacts",
    "android.permission.READ_EXTERNAL_STORAGE":
        "read the contents of shared external storage",
    "android.permission.READ_MEDIA_AUDIO":
        "read the device's audio files",
    "android.permission.READ_MEDIA_IMAGES":
        "read the device's image files",
    "android.permission.READ_MEDIA_VIDEO":
        "read the device's video files",
    "android.permission.READ_PHONE_NUMBERS":
        "read the device's phone number(s)",
    "android.permission.READ_PHONE_STATE":
        "read the device's phone state (calls, cell info)",
    "android.permission.READ_SMS":
        "read the device's SMS messages",
    "android.permission.READ_SYNC_SETTINGS":
        "read the device's sync settings",
    "android.permission.READ_SYNC_STATS":
        "read the device's sync statistics",
    "android.permission.READ_VOICEMAIL":
        "read the device's voicemails",
    "android.permission.REBOOT":
        "reboot the device",
    "android.permission.RECEIVE_BOOT_COMPLETED":
        "receive the broadcast when the system finishes booting",
    "android.permission.RECEIVE_MMS":
        "receive and process MMS messages",
    "android.permission.RECEIVE_SMS":
        "receive and process SMS messages",
    "android.permission.RECEIVE_WAP_PUSH":
        "receive and process WAP push messages",
    "android.permission.RECORD_AUDIO":
        "record audio with the microphone",
    "android.permission.REORDER_TASKS":
        "change the Z-order of running tasks",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS":
        "ask the user to ignore battery optimizations",
    "android.permission.REQUEST_INSTALL_PACKAGES":
        "request installing other packages (sideloading)",
    "android.permission.RESTART_PACKAGES":
        "kill other applications' processes (legacy)",
    "android.permission.SCHEDULE_EXACT_ALARM":
        "schedule exact alarms",
    "android.permission.SEND_SMS":
        "send SMS messages",
    "android.permission.SET_ALARM":
        "set an alarm in the system alarm app",
    "android.permission.SET_ALWAYS_FINISH":
        "control whether activities finish immediately when backgrounded",
    "android.permission.SET_ANIMATION_SCALE":
        "modify the global animation speed",
    "android.permission.SET_DEBUG_APP":
        "enable application debugging",
    "android.permission.SET_PROCESS_LIMIT":
        "set the maximum number of running processes",
    "android.permission.SET_TIME_ZONE":
        "set the device's time zone",
    "android.permission.SET_WALLPAPER":
        "set the device's wallpaper",
    "android.permission.SET_WALLPAPER_HINTS":
        "set the device's wallpaper size hints",
    "android.permission.SIGNAL_PERSISTENT_PROCESSES":
        "send persistent-process signals",
    "android.permission.SUBSCRIBED_FEEDS_READ":
        "read subscribed feeds",
    "android.permission.SUBSCRIBED_FEEDS_WRITE":
        "write to subscribed feeds",
    "android.permission.SYSTEM_ALERT_WINDOW":
        "draw on top of other applications",
    "android.permission.TRANSMIT_IR":
        "use the device's infrared transmitter",
    "android.permission.USE_BIOMETRIC":
        "use biometric authentication hardware",
    "android.permission.USE_FINGERPRINT":
        "use fingerprint hardware (legacy)",
    "android.permission.USE_SIP":
        "make/receive SIP (VoIP) calls",
    "android.permission.VIBRATE":
        "control the device's vibrator",
    "android.permission.WAKE_LOCK":
        "prevent the device from sleeping",
    "android.permission.WRITE_APN_SETTINGS":
        "write the device's APN settings",
    "android.permission.WRITE_CALENDAR":
        "add or modify calendar events",
    "android.permission.WRITE_CALL_LOG":
        "add or modify the device's call log",
    "android.permission.WRITE_CONTACTS":
        "add or modify the device's contacts",
    "android.permission.WRITE_EXTERNAL_STORAGE":
        "write to shared external storage",
    "android.permission.WRITE_SECURE_SETTINGS":
        "write the secure system settings",
    "android.permission.WRITE_SETTINGS":
        "modify the global system settings",
    "android.permission.WRITE_SMS":
        "write SMS messages",
    "android.permission.WRITE_SYNC_SETTINGS":
        "write the device's sync settings",
    "android.permission.WRITE_VOICEMAIL":
        "modify the device's voicemails",
}


def describe(name: str) -> Optional[str]:
    """Official-style description for a known platform permission, else None."""
    return PERMISSION_DESCRIPTIONS.get(str(name or "").strip())

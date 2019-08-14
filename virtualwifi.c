#include <linux/module.h>

#include <net/cfg80211.h> /* wiphy and probably everything that would required for FullMAC driver */
#include <linux/skbuff.h>

#include <linux/workqueue.h> /* work_struct */
#include <linux/semaphore.h>

#define WIPHY_NAME "navifly"
#define NDEV_NAME "navifly%d"
#define SSID_DUMMY "MyAwesomeWiFi"
#define SSID_DUMMY_SIZE (sizeof("MyAwesomeWiFi") - 1)

struct navifly_context {
    struct wiphy *wiphy;
    struct net_device *ndev;

    /* DEMO */
    struct semaphore sem;
    struct work_struct ws_connect;
    char connecting_ssid[sizeof(SSID_DUMMY)];
    struct work_struct ws_disconnect;
    u16 disconnect_reason_code;
    struct work_struct ws_scan;
    struct cfg80211_scan_request *scan_request;
};

struct navifly_wiphy_priv_context {
    struct navifly_context *navi;
};

struct navifly_ndev_priv_context {
    struct navifly_context *navi;
    struct wireless_dev wdev;
};

/* helper function that will retrieve main context from "priv" data of the wiphy */
static struct navifly_wiphy_priv_context *
wiphy_get_navi_context(struct wiphy *wiphy) { return (struct navifly_wiphy_priv_context *) wiphy_priv(wiphy); }

/* helper function that will retrieve main context from "priv" data of the network device */
static struct navifly_ndev_priv_context *
ndev_get_navi_context(struct net_device *ndev) { return (struct navifly_ndev_priv_context *) netdev_priv(ndev); }

/* Helper function that will prepare structure with "dummy" BSS information and "inform" the kernel about "new" BSS */
static void inform_dummy_bss(struct navifly_context *navi) {
    struct cfg80211_bss *bss = NULL;
    struct cfg80211_inform_bss data = {
            .chan = &navi->wiphy->bands[NL80211_BAND_2GHZ]->channels[0], /* the only channel for this demo */
            .scan_width = NL80211_BSS_CHAN_WIDTH_20,
            /* signal "type" not specified in this DEMO so its basically unused, it can be some kind of percentage from 0 to 100 or mBm value*/
            /* signal "type" may be specified before wiphy registration by setting wiphy->signal_type */
            .signal = 1337,
    };
    char bssid[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    /* ie - array of tags that usually retrieved from beacon frame or probe responce. */
    char ie[SSID_DUMMY_SIZE + 2] = {WLAN_EID_SSID, SSID_DUMMY_SIZE};
    memcpy(ie + 2, SSID_DUMMY, SSID_DUMMY_SIZE);

    /* also it posible to use cfg80211_inform_bss() instead of cfg80211_inform_bss_data() */
    bss = cfg80211_inform_bss_data(navi->wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, bssid, 0, WLAN_CAPABILITY_ESS, 100,
                                   ie, sizeof(ie), GFP_KERNEL);

    /* free, cfg80211_inform_bss_data() returning cfg80211_bss structure refcounter of which should be decremented if its not used. */
    cfg80211_put_bss(navi->wiphy, bss);
}

/* "Scan" routine for DEMO. It just inform the kernel about "dummy" BSS and "finishs" scan.
 * When scan is done it should call cfg80211_scan_done() to inform the kernel that scan is finished.
 * This routine called through workqueue, when the kernel asks about scan through cfg80211_ops. */
static void navifly_scan_routine(struct work_struct *w) {
    struct navifly_context *navi = container_of(w, struct navifly_context, ws_scan);
    struct cfg80211_scan_info info = {
            /* if scan was aborted by user(calling cfg80211_ops->abort_scan) or by any driver/hardware issue - field should be set to "true"*/
            .aborted = false,
    };

    /* pretend some work, also u can't call cfg80211_scan_done right away after cfg80211_ops->scan(),
     * idk why, but netlink client would not get message with "scan done",
     * is it because of "scan_routine" and cfg80211_ops->scan() may run in concurrent and cfg80211_scan_done() called before cfg80211_ops->scan() returns? */
    msleep(100);

    /* inform with dummy BSS */
    inform_dummy_bss(navi);

    if(down_interruptible(&navi->sem)) {
        return;
    }

    /* finish scan */
    cfg80211_scan_done(navi->scan_request, &info);

    navi->scan_request = NULL;

    up(&navi->sem);
}

/* It just checks SSID of the ESS to connect and informs the kernel that connect is finished.
 * It should call cfg80211_connect_bss() when connect is finished or cfg80211_connect_timeout() when connect is failed.
 * This "demo" can connect only to ESS with SSID equal to SSID_DUMMY value.
 * This routine called through workqueue, when the kernel asks about connect through cfg80211_ops. */
static void navifly_connect_routine(struct work_struct *w) {
    struct navifly_context *navi = container_of(w, struct navifly_context, ws_connect);

    if(down_interruptible(&navi->sem)) {
        return;
    }

    if (memcmp(navi->connecting_ssid, SSID_DUMMY, sizeof(SSID_DUMMY)) != 0) {
        cfg80211_connect_timeout(navi->ndev, NULL, NULL, 0, GFP_KERNEL, NL80211_TIMEOUT_SCAN);
    } else {
        /* we can connect to ESS that already know. If else, technically kernel will only warn.*/
        /* so, lets send dummy bss to the kernel before complete. */
        inform_dummy_bss(navi);

        /* also its possible to use cfg80211_connect_result() or cfg80211_connect_done() */
        cfg80211_connect_bss(navi->ndev, NULL, NULL, NULL, 0, NULL, 0, WLAN_STATUS_SUCCESS, GFP_KERNEL,
                             NL80211_TIMEOUT_UNSPECIFIED);
    }
    navi->connecting_ssid[0] = 0;

    up(&navi->sem);
}

/* Just calls cfg80211_disconnected() that informs the kernel that disconnect is complete.
 * Overall disconnect may call cfg80211_connect_timeout() if disconnect interrupting connection routine, but for this demo I keep it simple.
 * This routine called through workqueue, when the kernel asks about disconnect through cfg80211_ops. */
static void navifly_disconnect_routine(struct work_struct *w) {

    struct navifly_context *navi = container_of(w, struct navifly_context, ws_disconnect);

    if(down_interruptible(&navi->sem)) {
        return;
    }

    cfg80211_disconnected(navi->ndev, navi->disconnect_reason_code, NULL, 0, true, GFP_KERNEL);

    navi->disconnect_reason_code = 0;
    
    up(&navi->sem);
}

/* callback that called by the kernel when user decided to scan.
 * This callback should initiate scan routine(through work_struct) and exit with 0 if everything ok.
 * Scan routine should be finished with cfg80211_scan_done() call. */
static int nvf_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request) {
    struct navifly_context *navi = wiphy_get_navi_context(wiphy)->navi;

    if(down_interruptible(&navi->sem)) {
        return -ERESTARTSYS;
    }

    if (navi->scan_request != NULL) {
        up(&navi->sem);
        return -EBUSY;
    }
    navi->scan_request = request;

    up(&navi->sem);

    if (!schedule_work(&navi->ws_scan)) {
        return -EBUSY;
    }

    return 0; /* OK */
}

/* callback that called by the kernel when there is need to "connect" to some network.
 * It inits connection routine through work_struct and exits with 0 if everything ok.
 * connect routine should be finished with cfg80211_connect_bss()/cfg80211_connect_result()/cfg80211_connect_done() or cfg80211_connect_timeout(). */
static int nvf_connect(struct wiphy *wiphy, struct net_device *dev,
                struct cfg80211_connect_params *sme) {
    struct navifly_context *navi = wiphy_get_navi_context(wiphy)->navi;
    size_t ssid_len = sme->ssid_len > 15 ? 15 : sme->ssid_len;

    if(down_interruptible(&navi->sem)) {
        return -ERESTARTSYS;
    }

    memcpy(navi->connecting_ssid, sme->ssid, ssid_len);
    navi->connecting_ssid[ssid_len] = 0;

    up(&navi->sem);

    if (!schedule_work(&navi->ws_connect)) {
        return -EBUSY;
    }
    return 0;
}
/* callback that called by the kernel when there is need to "diconnect" from currently connected network.
 * It inits disconnect routine through work_struct and exits with 0 if everything ok.
 * disconnect routine should call cfg80211_disconnected() to inform the kernel that disconnection is complete. */
static int nvf_disconnect(struct wiphy *wiphy, struct net_device *dev,
                   u16 reason_code) {
    struct navifly_context *navi = wiphy_get_navi_context(wiphy)->navi;

    if(down_interruptible(&navi->sem)) {
        return -ERESTARTSYS;
    }

    navi->disconnect_reason_code = reason_code;

    up(&navi->sem);

    if (!schedule_work(&navi->ws_disconnect)) {
        return -EBUSY;
    }
    return 0;
}

/* Structure of functions for FullMAC 80211 drivers.
 * Functions that implemented along with fields/flags in wiphy structure would represent drivers features.
 * This DEMO can only perform "scan" and "connect".
 * Some functions cant be implemented alone, for example: with "connect" there is should be function "disconnect". */
static struct cfg80211_ops nvf_cfg_ops = {
        .scan = nvf_scan,
        .connect = nvf_connect,
        .disconnect = nvf_disconnect,
};

/* Network packet transmit.
 * Callback that called by the kernel when packet of data should be sent.
 * In this example it does nothing. */
static netdev_tx_t nvf_ndo_start_xmit(struct sk_buff *skb,
                               struct net_device *dev) {
    /* Dont forget to cleanup skb, as its ownership moved to xmit callback. */
    kfree_skb(skb);
    return NETDEV_TX_OK;
}

/* Structure of functions for network devices.
 * It should have at least ndo_start_xmit functions that called for packet to be sent. */
static struct net_device_ops nvf_ndev_ops = {
        .ndo_start_xmit = nvf_ndo_start_xmit,
};

/* Array of "supported" channels in 2ghz band. It's required for wiphy.
 * For demo - the only channel 6. */
static struct ieee80211_channel nvf_supported_channels_2ghz[] = {
        {
                .band = NL80211_BAND_2GHZ,
                .hw_value = 6,
                .center_freq = 2437,
        }
};

/* Array of supported rates. Its required to support at least those next rates for 2ghz band. */
static struct ieee80211_rate nvf_supported_rates_2ghz[] = {
        {
                .bitrate = 10,
                .hw_value = 0x1,
        },
        {
                .bitrate = 20,
                .hw_value = 0x2,
        },
        {
                .bitrate = 55,
                .hw_value = 0x4,
        },
        {
                .bitrate = 110,
                .hw_value = 0x8,
        }
};

/* Structure that describes supported band of 2ghz. */
static struct ieee80211_supported_band nf_band_2ghz = {
        .ht_cap.cap = IEEE80211_HT_CAP_SGI_20, /* add other band capabilities if needed, like 40 width etc. */
        .ht_cap.ht_supported = false,

        .channels = nvf_supported_channels_2ghz,
        .n_channels = ARRAY_SIZE(nvf_supported_channels_2ghz),

        .bitrates = nvf_supported_rates_2ghz,
        .n_bitrates = ARRAY_SIZE(nvf_supported_rates_2ghz),
};

/* Function that creates wiphy context and net_device with wireless_dev.
 * wiphy/net_device/wireless_dev is basic interfaces for the kernel to interact with driver as wireless one.
 * It returns driver's main "navifly" context. */
static struct navifly_context *navifly_create_context(void) {
    struct navifly_context *ret = NULL;
    struct navifly_wiphy_priv_context *wiphy_data = NULL;
    struct navifly_ndev_priv_context *ndev_data = NULL;

    /* allocate for navifly context*/
    ret = kmalloc(sizeof(*ret), GFP_KERNEL);
    if (!ret) {
        goto l_error;
    }

    /* allocate wiphy context, also it possible just to use wiphy_new() function.
     * wiphy should represent physical FullMAC wireless device.
     * One wiphy can have serveral network interfaces - for that u need to implement add_virtual_intf() and co. from cfg80211_ops. */
    ret->wiphy = wiphy_new_nm(&nvf_cfg_ops, sizeof(struct navifly_wiphy_priv_context), WIPHY_NAME);
    if (ret->wiphy == NULL) {
        goto l_error_wiphy;
    }

    /* save navifly context in wiphy private data. */
    wiphy_data = wiphy_get_navi_context(ret->wiphy);
    wiphy_data->navi = ret;

    /* set device object as wiphy "parent", I dont have any device yet. */
    /* set_wiphy_dev(ret->wiphy, dev); */

    /* wiphy should determinate it type */
    /* add other required types like  "BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP)" etc. */
    ret->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

    /* wiphy should have at least 1 band. */
    /* fill also NL80211_BAND_5GHZ if required, in this small example I use only 1 band with 1 "channel" */
    ret->wiphy->bands[NL80211_BAND_2GHZ] = &nf_band_2ghz;

    /* scan - if ur device supports "scan" u need to define max_scan_ssids at least. */
    ret->wiphy->max_scan_ssids = 69;

    /* register wiphy, if everything ok - there should be another wireless device in system.
     * use command:
     *     $ iw list
     *     Wiphy navifly
     *     ...
     * */
    if (wiphy_register(ret->wiphy) < 0) {
        goto l_error_wiphy_register;
    }

    /* allocate network device context. */
    ret->ndev = alloc_netdev(sizeof(*ndev_data), NDEV_NAME, NET_NAME_ENUM, ether_setup);
    if (ret->ndev == NULL) {
        goto l_error_alloc_ndev;
    }
    /* fill private data of network context.*/
    ndev_data = ndev_get_navi_context(ret->ndev);
    ndev_data->navi = ret;

    /* fill wireless_dev context.
     * wireless_dev with net_device can be represented as inherited class of single net_device. */
    ndev_data->wdev.wiphy = ret->wiphy;
    ndev_data->wdev.netdev = ret->ndev;
    ndev_data->wdev.iftype = NL80211_IFTYPE_STATION;
    ret->ndev->ieee80211_ptr = &ndev_data->wdev;

    /* set device object for net_device */
    /* SET_NETDEV_DEV(ret->ndev, wiphy_dev(ret->wiphy)); */

    /* set network device hooks. It should implement ndo_start_xmit() at least. */
    ret->ndev->netdev_ops = &nvf_ndev_ops;

    /* Add here proper net_device initialization. */

    /* register network device. If everything ok, there should be new network device:
     *     $ ip a
     *     ...
     *     4: navifly0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
     *         link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
     *     ...
     * */
    if (register_netdev(ret->ndev)) {
        goto l_error_ndev_register;
    }

    return ret;
    l_error_ndev_register:
    free_netdev(ret->ndev);
    l_error_alloc_ndev:
    wiphy_unregister(ret->wiphy);
    l_error_wiphy_register:
    wiphy_free(ret->wiphy);
    l_error_wiphy:
    kfree(ret);
    l_error:
    return NULL;
}

static void navifly_free(struct navifly_context *ctx) {
    if (ctx == NULL) {
        return;
    }

    unregister_netdev(ctx->ndev);
    free_netdev(ctx->ndev);
    wiphy_unregister(ctx->wiphy);
    wiphy_free(ctx->wiphy);
    kfree(ctx);
}

static struct navifly_context *g_ctx = NULL;

static int __init virtual_wifi_init(void) {
    g_ctx = navifly_create_context();

    if (g_ctx != NULL) {
        /*DEMO*/
        sema_init(&g_ctx->sem, 1);
        INIT_WORK(&g_ctx->ws_connect, navifly_connect_routine);
        g_ctx->connecting_ssid[0] = 0;
        INIT_WORK(&g_ctx->ws_disconnect, navifly_disconnect_routine);
        g_ctx->disconnect_reason_code = 0;
        INIT_WORK(&g_ctx->ws_scan, navifly_scan_routine);
        g_ctx->scan_request = NULL;
    }
    return g_ctx == NULL;
}

static void __exit virtual_wifi_exit(void) {
    /* make sure that no work is queued */
    cancel_work_sync(&g_ctx->ws_connect);
    cancel_work_sync(&g_ctx->ws_disconnect);
    cancel_work_sync(&g_ctx->ws_scan);

    navifly_free(g_ctx);
}

module_init(virtual_wifi_init);
module_exit(virtual_wifi_exit);

MODULE_LICENSE("GPL v2");

MODULE_DESCRIPTION("Dumb example for cfg80211(aka FullMAC) driver."
                   "Module creates wireless device with network."
                   "The device can work as station(STA mode) only."
                   "The device can perform scan that \"scans\" only dummy network."
                   "Also it performs \"connect\" to the dummy network.");
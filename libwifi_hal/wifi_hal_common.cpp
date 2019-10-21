/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hardware_legacy/wifi.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include <android-base/logging.h>
#include <cutils/misc.h>
#include <cutils/properties.h>
#include <sys/syscall.h>

#define finit_module(fd, opts, flags) syscall(SYS_finit_module, fd, opts, flags)

#ifdef MULTI_WIFI_SUPPORT
#include <dlfcn.h>
typedef int (*WIFI_LOAD_DRIVER) ();
typedef int (*WIFI_UNLOAD_DRIVER) ();
typedef int (*WIFI_CHANGE_FW_PATH) (const char *fwpath);
typedef const char * (*WIFI_GET_FW_PATH) (int fw_type);
typedef const char * (*WIFI_GET_VENDOR_NAME) ();

void* pHandle = NULL;

void* init_multi_wifi_handle() {
  if (pHandle == NULL) {
    pHandle = dlopen("libwifi-hal-common-ext.so", RTLD_NOW);
    if (pHandle == NULL) {
      PLOG(ERROR) << "Unable to get multi wifi so";
      return NULL;
    }
  }
  return pHandle;
}

void release_multi_wifi_handle() {
  if (pHandle != NULL) {
    dlclose(pHandle);
    pHandle = NULL;
  }
}

int wifi_load_driver_ext() {
  void* handle = init_multi_wifi_handle();
  if (handle != NULL) {
    WIFI_LOAD_DRIVER pFunc = (WIFI_LOAD_DRIVER)dlsym(handle, "_Z20wifi_load_driver_extv");
    if (pFunc == NULL) {
      LOG(ERROR) << "Unable to get multi wifi wifi_load_driver_ext function";
      return -1;
    }
    return pFunc();
  }
  return -1;
}

int wifi_unload_driver_ext() {
  void* handle = init_multi_wifi_handle();
  if (handle != NULL) {
    WIFI_UNLOAD_DRIVER pFunc = (WIFI_UNLOAD_DRIVER)dlsym(handle, "_Z22wifi_unload_driver_extv");
    if (pFunc == NULL) {
      LOG(ERROR) << "Unable to get multi wifi wifi_unload_driver_ext function";
      return -1;
    }

    int ret = pFunc();
    release_multi_wifi_handle();
    return ret;
  }

  return -1;
}

const char *wifi_get_fw_path_ext(int fw_type) {
  void* handle = init_multi_wifi_handle();
  if (handle != NULL) {
    WIFI_GET_FW_PATH pFunc = (WIFI_GET_FW_PATH)dlsym(handle, "_Z20wifi_get_fw_path_exti");
    if (pFunc == NULL) {
      LOG(ERROR) << "Unable to get multi wifi wifi_get_fw_path_ext function";
      return NULL;
    }
    return pFunc(fw_type);
  }

  return NULL;
}

int wifi_change_fw_path_ext(const char *fwpath) {
  void* handle = init_multi_wifi_handle();
  if (handle != NULL) {
    WIFI_CHANGE_FW_PATH pFunc = (WIFI_CHANGE_FW_PATH)dlsym(handle, "_Z23wifi_change_fw_path_extPKc");
    if (pFunc == NULL) {
      LOG(ERROR) << "Unable to get multi wifi wifi_change_fw_path_ext function";
      return -1;
    }
    return pFunc(fwpath);
  }

  return -1;
}

const char *get_wifi_vendor_name() {
  void* handle = init_multi_wifi_handle();
  if (handle != NULL) {
    WIFI_GET_VENDOR_NAME pFunc = (WIFI_GET_VENDOR_NAME)dlsym(handle, "_Z20get_wifi_vendor_namev");
    if (pFunc == NULL) {
      LOG(ERROR) << "Unable to get multi wifi get_wifi_vendor_name function";
      return NULL;
    }
    return pFunc();
  }

  return NULL;
}
#endif
extern "C" int init_module(void *, unsigned long, const char *);
extern "C" int delete_module(const char *, unsigned int);

#ifndef WIFI_DRIVER_FW_PATH_STA
#define WIFI_DRIVER_FW_PATH_STA NULL
#endif
#ifndef WIFI_DRIVER_FW_PATH_AP
#define WIFI_DRIVER_FW_PATH_AP NULL
#endif
#ifndef WIFI_DRIVER_FW_PATH_P2P
#define WIFI_DRIVER_FW_PATH_P2P NULL
#endif

#ifndef WIFI_DRIVER_MODULE_ARG
#define WIFI_DRIVER_MODULE_ARG ""
#endif

static const char DRIVER_PROP_NAME[] = "wlan.driver.status";
static const char DRIVER_PROP_TAG[] = "wlan.driver.tag";
#ifdef WIFI_DRIVER_MODULE_PATH
static const char DRIVER_MODULE_ARG[] = WIFI_DRIVER_MODULE_ARG;
static const char MODULE_FILE[] = "/proc/modules";
#endif

static int insmod(const char *filename, const char *args) {
  int ret;
#ifdef MULTI_WIFI_SUPPORT
  void *module;
  unsigned int size;

  module = load_file(filename, &size);
  if (!module) return -1;

  //ret = init_module(module, size, args);
  ret = finit_module(module, args, 0);

  free(module);
#else
  int fd;

  fd = TEMP_FAILURE_RETRY(open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd < 0) {
    PLOG(ERROR) << "Failed to open " << filename;
    return -1;
  }

  ret = syscall(__NR_finit_module, fd, args, 0);

  close(fd);
  if (ret < 0) {
    PLOG(ERROR) << "finit_module return: " << ret;
  }

#endif

  return ret;
}

static int rmmod(const char *modname) {
  int ret = -1;
  int maxtry = 10;

  while (maxtry-- > 0) {
    ret = delete_module(modname, O_NONBLOCK | O_EXCL);
    if (ret < 0 && errno == EAGAIN)
      usleep(500000);
    else
      break;
  }

  if (ret != 0)
    PLOG(DEBUG) << "Unable to unload driver module '" << modname << "'";
  return ret;
}

#ifdef WIFI_DRIVER_STATE_CTRL_PARAM
int wifi_change_driver_state(const char *state) {
  int len;
  int fd;
  int ret = 0;

  if (!state) return -1;
  fd = TEMP_FAILURE_RETRY(open(WIFI_DRIVER_STATE_CTRL_PARAM, O_WRONLY));
  if (fd < 0) {
    PLOG(ERROR) << "Failed to open driver state control param";
    return -1;
  }
  len = strlen(state) + 1;
  if (TEMP_FAILURE_RETRY(write(fd, state, len)) != len) {
    PLOG(ERROR) << "Failed to write driver state control param";
    ret = -1;
  }
  close(fd);
  return ret;
}
#endif

static struct wifi_modules {
  int vid;
  int pid;
  char tag[32];
  char modules[16][PATH_MAX];
  int nr_modules;
} wifi_modules = {
  .nr_modules = 0,
};

int is_wifi_driver_loaded() {
  char driver_status[PROPERTY_VALUE_MAX];
#ifdef WIFI_DRIVER_MODULE_PATH
  FILE *proc;
  char line[32];
#endif

  if (!property_get(DRIVER_PROP_NAME, driver_status, NULL) ||
      strcmp(driver_status, "ok") != 0) {
    return 0; /* driver not loaded */
  }
#ifdef WIFI_DRIVER_MODULE_PATH
  /*
   * If the property says the driver is loaded, check to
   * make sure that the property setting isn't just left
   * over from a previous manual shutdown or a runtime
   * crash.
   */
  if ((proc = fopen(MODULE_FILE, "r")) == NULL) {
    PLOG(WARNING) << "Could not open " << MODULE_FILE;
    property_set(DRIVER_PROP_NAME, "unloaded");
    return 0;
  }
  while ((fgets(line, sizeof(line), proc)) != NULL) {
    if (strncmp(line, wifi_modules.tag, strlen(wifi_modules.tag)) == 0) {
      fclose(proc);
      return 1;
    }
  }
  fclose(proc);
  property_set(DRIVER_PROP_NAME, "unloaded");
  return 0;
#else
  return 1;
#endif
}

struct wifi_usbdev *gWifiUSBdev;

static int wifi_usb_read_id(const char* entry, int *vid, int *pid)
{
  char buf[4 + 1] = {'\0', };
  char node[50];
  int fd = -1;

  sprintf(node, "/sys/bus/usb/devices/%s/idVendor", entry);
  fd = open(node, O_RDONLY);
  if (fd < 0)
    return -ENOENT;

  read(fd, buf, 4);
  close(fd);

  *vid = strtol(buf, NULL, 16);

  sprintf(node, "/sys/bus/usb/devices/%s/idProduct", entry);
  fd = open(node, O_RDONLY);
  if (fd < 0)
    return -ENOENT;

  read(fd, buf, 4);
  close(fd);

  *pid = strtol(buf, NULL, 16);

  return 0;
}

static char* path2tag(const char* path, char* tag)
{
  int len;
  char *p = (char *)strrchr(path, '/');


  strcpy(tag, p + 1);    /* Ingnore the first '/' start with */
  len = strlen(tag) - 3;    /* 3 = strlen(".ko") */

  /* truncate ".ko" extension from driver name */
  if (!strcmp(tag + len, ".ko"))
      *(char*)(tag + len) = 0;

  /* replace '-' to '_' in the driver name since '_' is used in module
   * name intead of '-' when it is loaded
   */
  while (len--)
    if (tag[len] == '-')
      tag[len] = '_';

  return tag;
}

int load_wifi_list(struct wifi_modules* drv)
{
    FILE *fp;
    char line[128];
    int vid, pid;
    char tag[32], probe[PATH_MAX];
    int found = 0;
    int i = 0;

    if ((fp = fopen("/vendor/etc/wifi_id_list.txt", "r")) == NULL)
        return 0;

    /*
     * scan the USB list with VID:PID attached
     */
    while (fgets(line, sizeof(line), fp)) {
        sscanf(line, "%04x %04x %s %s", &vid, &pid, tag, probe);
        if ((drv->vid == vid) && (drv->pid == pid)) {
            LOG(INFO) << "USB WiFi device is detected, [" 
                << std::hex << drv->vid << ":" << std::hex << drv->pid << "]";
            found = 1;
            break;
        }
    }
    fclose(fp);

    if (!found)
        return 0;

    /*
     * 'probe' stores the specific driver list to load
     */
    if ((fp = fopen(probe, "r")) == NULL)
        return 0;

    drv->nr_modules = 0;
    for (i = 0; i < (int)(sizeof(drv->modules) / sizeof(drv->modules[0])); i++) {
        if (fgets(drv->modules[i], sizeof(drv->modules[i]) - 1, fp) == NULL) {
            path2tag(drv->modules[i - 1], drv->tag);
            drv->nr_modules = i;
            break;
        }
        /* truncate '\n' at the end of line */
        drv->modules[i][strlen(drv->modules[i]) - 1] = 0;
    }

    fclose(fp);

    return drv->nr_modules;
}

int wifi_load_driver() {
#ifdef WIFI_DRIVER_MODULE_PATH
#ifdef MULTI_WIFI_SUPPORT
  if (wifi_load_driver_ext() != 0) {
    return -1;
  } else {
    if (strncmp(get_wifi_vendor_name(), "bcm", 3) == 0)
      property_set(DRIVER_PROP_NAME, "ok");

    return 0;
  }
#endif

  int i = 0;

  DIR *dir = opendir("/sys/bus/usb/devices/");
  if (dir == NULL)
    return 0;

  struct dirent *dent;

  int vid, pid;
  int err;
  while ((dent = readdir(dir)) != NULL) {
    vid = 0;
    pid = 0;
    err = -1;

    err = wifi_usb_read_id(dent->d_name, &vid, &pid);
    if (err < 0)
      continue;

    wifi_modules.vid = vid;
    wifi_modules.pid = pid;
    if (load_wifi_list(&wifi_modules))
        break;
  }
  closedir(dir);

  if (wifi_modules.nr_modules == 0)
    return -1;

  //strcpy((char *)DRIVER_MODULE_TAG, wifi_modules.tag);

  if (is_wifi_driver_loaded()) {
    return 0;
  }

  for (i = 0; i < wifi_modules.nr_modules; i++) {
    char *drv = wifi_modules.modules[i];
    LOG(INFO) << "Loading " << drv;
    if (insmod(drv, DRIVER_MODULE_ARG) < 0)
      return -1;
    usleep(200000);
  }
  property_set(DRIVER_PROP_TAG, wifi_modules.tag);
#endif

#ifdef WIFI_DRIVER_STATE_CTRL_PARAM
  if (is_wifi_driver_loaded()) {
    return 0;
  }

  if (wifi_change_driver_state(WIFI_DRIVER_STATE_ON) < 0) return -1;
#endif
  property_set(DRIVER_PROP_NAME, "ok");
  return 0;
}

int wifi_unload_driver() {
#ifdef MULTI_WIFI_SUPPORT
  wifi_unload_driver_ext();
  property_set(DRIVER_PROP_NAME, "unloaded");
  return 0;
#endif

  if (!is_wifi_driver_loaded()) {
    return 0;
  }
  char drvname[80];
  usleep(200000); /* allow to finish interface down */
#ifdef WIFI_DRIVER_MODULE_PATH
  while (wifi_modules.nr_modules > 0) {
    wifi_modules.nr_modules--;
    path2tag(wifi_modules.modules[wifi_modules.nr_modules], drvname);
    if (rmmod(drvname) == 0) {
      int count = 20; /* wait at most 10 seconds for completion */
      while (count-- > 0) {
        if (!is_wifi_driver_loaded()) break;
        usleep(500000);
      }
      usleep(500000); /* allow card removal */
    }
  }
  property_set(DRIVER_PROP_TAG, "");
#else
#ifdef WIFI_DRIVER_STATE_CTRL_PARAM
  if (is_wifi_driver_loaded()) {
    if (wifi_change_driver_state(WIFI_DRIVER_STATE_OFF) < 0) return -1;
  }
#endif
#endif
  property_set(DRIVER_PROP_NAME, "unloaded");
  return 0;
}

const char *wifi_get_fw_path(int fw_type) {
#ifdef MULTI_WIFI_SUPPORT
  return wifi_get_fw_path_ext(fw_type);
#endif

  switch (fw_type) {
    case WIFI_GET_FW_PATH_STA:
      return WIFI_DRIVER_FW_PATH_STA;
    case WIFI_GET_FW_PATH_AP:
      return WIFI_DRIVER_FW_PATH_AP;
    case WIFI_GET_FW_PATH_P2P:
      return WIFI_DRIVER_FW_PATH_P2P;
  }
  return NULL;
}

int wifi_change_fw_path(const char *fwpath) {
  int len;
  int fd;
  int ret = 0;
#ifdef MULTI_WIFI_SUPPORT
  return wifi_change_fw_path_ext(fwpath);
#endif

  if (!fwpath) return ret;
  fd = TEMP_FAILURE_RETRY(open(WIFI_DRIVER_FW_PATH_PARAM, O_WRONLY));
  if (fd < 0) {
    PLOG(ERROR) << "Failed to open wlan fw path param";
    return -1;
  }
  len = strlen(fwpath) + 1;
  if (TEMP_FAILURE_RETRY(write(fd, fwpath, len)) != len) {
    PLOG(ERROR) << "Failed to write wlan fw path param";
    ret = -1;
  }
  close(fd);
  return ret;
}

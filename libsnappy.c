/* Copyright 2018-2019 Sam Bingner All Rights Reserved
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/snapshot.h>
#include <strings.h>
#include <getopt.h>
#import <CoreFoundation/CoreFoundation.h>
#if __has_include(<IOKit/IOKitLib.h>)
#include <IOKit/IOKitLib.h>
#else
#include <mach/error.h>
typedef mach_port_t     io_object_t;
typedef io_object_t     io_registry_entry_t;
typedef char            io_string_t[512];
typedef UInt32          IOOptionBits;

extern const mach_port_t kIOMasterPortDefault;

io_registry_entry_t IORegistryEntryFromPath(mach_port_t masterPort, const io_string_t path);
CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
kern_return_t IOObjectRelease(io_object_t object );
#endif
#include "snappy.h"

static char *copyBootHash(void);
#define APPLESNAP "com.apple.os.update-"

bool READ_NEW_IORegistryEntry = true;

__attribute__((aligned(4)))
typedef struct val_attrs {
	uint32_t		length;
	attribute_set_t		returned;
	attrreference_t		name_info;
	char			name[MAXPATHLEN];
} val_attrs_t;

bool snapshot_check(int dirfd, const char *name)
{
    const char **snapshots = copy_snapshot_list(dirfd);
    if (snapshots == NULL) {
        return false;
    }
    for (const char **snapshot = snapshots; *snapshot; snapshot++) {
        if (strcmp(name, *snapshot)==0) {
            free(snapshots);
            return true;
        }
    }
    free(snapshots);
    return false;
}

const char *copy_first_snapshot(int dirfd)
{
    char *snapshot = NULL;

    const char **snapshots = copy_snapshot_list(dirfd);
    if (!snapshots) return NULL;
    if (snapshots[0]) {
        snapshot = strdup(snapshots[0]);
    }
    free(snapshots);
    return snapshot;
}

const char **copy_snapshot_list(int dirfd)
{
	uint64_t nameOffset = 257 * sizeof(char *);
	uint64_t snapshots_size = nameOffset + MAXPATHLEN;
	char **snapshots = (char **)calloc(snapshots_size, sizeof(char));
	struct attrlist attr_list = { 0 };

        if (snapshots == NULL) {
            perror("Unable to allocate memory for snapshot names");
            return NULL;
        }

	attr_list.commonattr = ATTR_BULK_REQUIRED;

	val_attrs_t buf;
	bzero(&buf, sizeof(buf));
	int retcount;
	int snapidx = 0;
	while ((retcount = fs_snapshot_list(dirfd, &attr_list, &buf, sizeof(buf), 0))>0) {
		val_attrs_t *entry = &buf;

                int i;
                for (i=0; i<retcount; i++) {
			if (entry->returned.commonattr & ATTR_CMN_NAME) {
				size_t size = strlen(entry->name) + 1;
				if (snapidx > 255) {
					fprintf(stderr, "Too many snapshots to handle\n");
					return (const char **)snapshots;
				}
				if (nameOffset + size > snapshots_size) {
					snapshots_size += MAXPATHLEN;
					snapshots = (char **)reallocf(snapshots, snapshots_size);
                                        if (snapshots == NULL) {
                                            perror("Couldn't realloc snapshot buffer");
                                            return NULL;
                                        }
				}
				snapshots[snapidx] = (char *)snapshots + nameOffset;
				nameOffset += size;
				strncpy(snapshots[snapidx], entry->name, size);
                                snapidx++;
                        }

			entry = (val_attrs_t *)((char *)entry + entry->length);
		}
                bzero(&buf, sizeof(buf));
        }

	if (retcount < 0) {
		perror("fs_snapshot_list");
		return nil;
	}

	return (const char **)snapshots;
}

static int sha1_to_str(const unsigned char *hash, size_t hashlen, char *buf, size_t buflen)
{
	if (buflen < (hashlen*2+1)) {
		return -1;
	}

	int i;
	for (i=0; i<hashlen; i++) {
		sprintf(buf+i*2, "%02X", hash[i]);
	}
	buf[i*2] = 0;
	return ERR_SUCCESS;
}

static char *copyBootHash(void)
{
	io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");

	if (!MACH_PORT_VALID(chosen)) {
		printf("Unable to get IODeviceTree:/chosen port\n");
		return NULL;
	}

    CFDataRef hash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("root-snapshot-name"), kCFAllocatorDefault, 0);

    if (hash == nil) {
        READ_NEW_IORegistryEntry = false;
        hash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    }

	IOObjectRelease(chosen);

	if (hash == nil) {
		fprintf(stderr, "Unable to read neither root-snapshot-name nor boot-manifest-hash\n");
		return NULL;
	}

	if (CFGetTypeID(hash) != CFDataGetTypeID()) {
		fprintf(stderr, "Error hash is not data type\n");
		CFRelease(hash);
		return NULL;
	}

	// Make a hex string out of the hash

    char *manifestHash;

    if (READ_NEW_IORegistryEntry) {
        CFStringRef root_snapshot_name = CFStringCreateFromExternalRepresentation(NULL, hash, kCFStringEncodingUTF8);
        CFRelease(hash);
        CFIndex length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(root_snapshot_name), kCFStringEncodingUTF8) + 1;
        manifestHash = (char*)calloc(length, sizeof(char));

        CFStringGetCString(root_snapshot_name, manifestHash, length, kCFStringEncodingUTF8);

        CFRelease(root_snapshot_name);
    } else {
        CFIndex length = CFDataGetLength(hash) * 2 + 1;
        manifestHash = (char*)calloc(length, sizeof(char));

        int ret = sha1_to_str(CFDataGetBytePtr(hash), CFDataGetLength(hash), manifestHash, length);

        CFRelease(hash);

        if (ret != ERR_SUCCESS) {
            printf("Unable to generate bootHash string\n");
            free(manifestHash);
            return NULL;
        }
    }

	return manifestHash;
}

char *copy_system_snapshot()
{
    char *hash = copyBootHash();
    if (READ_NEW_IORegistryEntry) {
        return hash;
    } else {
        if (hash == NULL) {
            return NULL;
        }
        char *hashsnap = malloc(strlen(APPLESNAP) + strlen(hash) + 1);
        strcpy(hashsnap, APPLESNAP);
        strcpy(hashsnap + strlen(APPLESNAP), hash);
        free(hash);
        return hashsnap;
    }
}

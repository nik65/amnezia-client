// SPDX-License-Identifier: Apache-2.0
#include "union_bridge.h"
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

struct union_bridge {
    JavaVM *vm;
    jobject callbacks;
    jmethodID protect;
    jmethodID owner;
    pthread_mutex_t mutex;
    pthread_cond_t idle;
    unsigned int active;
    int released;
};

static int union_enter(struct union_bridge *bridge)
{
    int entered = 0;
    pthread_mutex_lock(&bridge->mutex);
    if (!bridge->released) {
        bridge->active++;
        entered = 1;
    }
    pthread_mutex_unlock(&bridge->mutex);
    return entered;
}

static void union_leave(struct union_bridge *bridge)
{
    pthread_mutex_lock(&bridge->mutex);
    bridge->active--;
    if (bridge->released && bridge->active == 0)
        pthread_cond_signal(&bridge->idle);
    pthread_mutex_unlock(&bridge->mutex);
}

static JNIEnv *union_env(struct union_bridge *bridge, int *attached)
{
    JNIEnv *env = NULL;
    *attached = 0;
    jint status = (*bridge->vm)->GetEnv(bridge->vm, (void **)&env, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if ((*bridge->vm)->AttachCurrentThread(bridge->vm, &env, NULL) != JNI_OK)
            return NULL;
        *attached = 1;
    } else if (status != JNI_OK) {
        return NULL;
    }
    return env;
}

int amnezia_union_protect(uintptr_t opaque, int fd)
{
    struct union_bridge *bridge = (struct union_bridge *)opaque;
    if (!bridge || !union_enter(bridge)) return 0;
    int attached;
    JNIEnv *env = union_env(bridge, &attached);
    if (!env) {
        union_leave(bridge);
        return 0;
    }
    jboolean result = (*env)->CallBooleanMethod(env, bridge->callbacks, bridge->protect, fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        result = JNI_FALSE;
    }
    if (attached) (*bridge->vm)->DetachCurrentThread(bridge->vm);
    union_leave(bridge);
    return result == JNI_TRUE;
}

int amnezia_union_owner(uintptr_t opaque, int protocol, const void *source, int source_length,
                int source_port, const void *destination, int destination_length, int destination_port)
{
    struct union_bridge *bridge = (struct union_bridge *)opaque;
    if (!bridge || !union_enter(bridge)) return -1;
    int attached;
    JNIEnv *env = union_env(bridge, &attached);
    if (!env) {
        union_leave(bridge);
        return -1;
    }
    jint result = -1;
    jbyteArray source_bytes = (*env)->NewByteArray(env, source_length);
    jbyteArray destination_bytes = (*env)->NewByteArray(env, destination_length);
    if (!source_bytes || !destination_bytes) goto cleanup;
    (*env)->SetByteArrayRegion(env, source_bytes, 0, source_length, source);
    (*env)->SetByteArrayRegion(env, destination_bytes, 0, destination_length, destination);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    result = (*env)->CallIntMethod(env, bridge->callbacks, bridge->owner,
                                  protocol, source_bytes, source_port, destination_bytes, destination_port);
cleanup:
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        result = -1;
    }
    if (source_bytes) (*env)->DeleteLocalRef(env, source_bytes);
    if (destination_bytes) (*env)->DeleteLocalRef(env, destination_bytes);
    if (attached) (*bridge->vm)->DetachCurrentThread(bridge->vm);
    union_leave(bridge);
    return result;
}

void amnezia_union_release(uintptr_t opaque)
{
    struct union_bridge *bridge = (struct union_bridge *)opaque;
    if (!bridge) return;
    pthread_mutex_lock(&bridge->mutex);
    bridge->released = 1;
    while (bridge->active != 0)
        pthread_cond_wait(&bridge->idle, &bridge->mutex);
    pthread_mutex_unlock(&bridge->mutex);
    int attached;
    JNIEnv *env = union_env(bridge, &attached);
    if (env) {
        (*env)->DeleteGlobalRef(env, bridge->callbacks);
        if (attached) (*bridge->vm)->DetachCurrentThread(bridge->vm);
    }
    pthread_cond_destroy(&bridge->idle);
    pthread_mutex_destroy(&bridge->mutex);
    free(bridge);
}

struct go_string { const char *str; long n; };
extern int awgTurnOnUnion(struct go_string name, int fd, struct go_string settings,
                         uintptr_t callbacks, struct go_string policy);

JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_awgTurnOnUnion(
    JNIEnv *env, jobject backend, jstring name, jint fd, jstring settings, jobject callbacks, jstring policy)
{
    (void)backend;
    if (!name || !settings || !callbacks || !policy) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        close(fd);
        return -1;
    }
    struct union_bridge *bridge = calloc(1, sizeof(*bridge));
    if (!bridge) { close(fd); return -1; }
    if (pthread_mutex_init(&bridge->mutex, NULL) != 0) {
        free(bridge);
        close(fd);
        return -1;
    }
    if (pthread_cond_init(&bridge->idle, NULL) != 0) {
        pthread_mutex_destroy(&bridge->mutex);
        free(bridge);
        close(fd);
        return -1;
    }
    if ((*env)->GetJavaVM(env, &bridge->vm) != JNI_OK) {
        pthread_cond_destroy(&bridge->idle);
        pthread_mutex_destroy(&bridge->mutex);
        free(bridge);
        close(fd);
        return -1;
    }
    bridge->callbacks = (*env)->NewGlobalRef(env, callbacks);
    jclass type = (*env)->GetObjectClass(env, callbacks);
    if (!bridge->callbacks || !type) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        amnezia_union_release((uintptr_t)bridge);
        close(fd);
        return -1;
    }
    bridge->protect = (*env)->GetMethodID(env, type, "protectSocket", "(I)Z");
    bridge->owner = (*env)->GetMethodID(env, type, "ownerSelected", "(I[BI[BI)I");
    (*env)->DeleteLocalRef(env, type);
    if (!bridge->protect || !bridge->owner || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        amnezia_union_release((uintptr_t)bridge);
        close(fd);
        return -1;
    }
    const char *name_text = (*env)->GetStringUTFChars(env, name, NULL);
    const char *settings_text = (*env)->GetStringUTFChars(env, settings, NULL);
    const char *policy_text = (*env)->GetStringUTFChars(env, policy, NULL);
    int result = -1;
    if (name_text && settings_text && policy_text) {
        result = awgTurnOnUnion(
            (struct go_string){name_text, (*env)->GetStringUTFLength(env, name)}, fd,
            (struct go_string){settings_text, (*env)->GetStringUTFLength(env, settings)}, (uintptr_t)bridge,
            (struct go_string){policy_text, (*env)->GetStringUTFLength(env, policy)});
    } else close(fd);
    if (name_text) (*env)->ReleaseStringUTFChars(env, name, name_text);
    if (settings_text) (*env)->ReleaseStringUTFChars(env, settings, settings_text);
    if (policy_text) (*env)->ReleaseStringUTFChars(env, policy, policy_text);
    // Successful handles own the bridge until Device.Close has joined readers.
    if (result < 0) amnezia_union_release((uintptr_t)bridge);
    return result;
}

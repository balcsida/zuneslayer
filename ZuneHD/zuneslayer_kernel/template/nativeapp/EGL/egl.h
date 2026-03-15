/* Minimal EGL type stubs for compclient.h include chain */
#ifndef __egl_h_
#define __egl_h_

typedef int EGLint;
typedef unsigned int EGLBoolean;
typedef void *EGLDisplay;
typedef void *EGLSurface;
typedef void *EGLContext;
typedef void *EGLConfig;
typedef void *EGLNativeDisplayType;
typedef void *EGLNativeWindowType;
typedef void *EGLNativePixmapType;
typedef void *EGLClientBuffer;
typedef void *EGLImageKHR;

#define EGL_DEFAULT_DISPLAY ((EGLNativeDisplayType)0)
#define EGL_NO_DISPLAY ((EGLDisplay)0)
#define EGL_NO_SURFACE ((EGLSurface)0)
#define EGL_NO_CONTEXT ((EGLContext)0)
#define EGL_FALSE 0
#define EGL_TRUE 1

typedef EGLBoolean (*PFNEGLLOCKSURFACEKHRPROC)(EGLDisplay, EGLSurface, const EGLint*);
typedef EGLBoolean (*PFNEGLUNLOCKSURFACEKHRPROC)(EGLDisplay, EGLSurface);
typedef EGLImageKHR (*PFNEGLCREATEIMAGEKHRPROC)(EGLDisplay, EGLContext, int, EGLClientBuffer, const EGLint*);
typedef EGLBoolean (*PFNEGLDESTROYIMAGEKHRPROC)(EGLDisplay, EGLImageKHR);

#endif

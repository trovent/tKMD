#pragma once
#define METHOD_NEITHER                  3
#define FILE_ANY_ACCESS                 0
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define tKMD_DEVICE 0x8000
#define IOCTL_CALLBACK_PROCESS CTL_CODE(tKMD_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CALLBACK_THREAD CTL_CODE(tKMD_DEVICE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CALLBACK_IMAGE CTL_CODE(tKMD_DEVICE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
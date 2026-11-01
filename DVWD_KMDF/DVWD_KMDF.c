/*
 * KmdfDriver.c - KMDF version of the skeleton driver, with three IOCTL
 *                handlers: do_terminate, do_read, do_write
 *
 * Model:  non-PnP KMDF driver exposing one "control device" (no hardware).
 * Build:  Visual Studio + WDK, "Kernel Mode Driver, Empty (KMDF)" template.
 * Test:   load only on a test VM / test-signed machine.
 */

#include <ntddk.h>
#include <wdf.h>

 /* ------------------------------------------------------------------ */
 /* Names                                                               */
 /* ------------------------------------------------------------------ */

#define DEVICE_NAME_W   L"\\Device\\MyKmdfDriver"
#define SYMLINK_NAME_W  L"\\DosDevices\\MyKmdfDriver"

/* ------------------------------------------------------------------ */
/* IOCTL codes (identical to the WDM version)                          */
/* ------------------------------------------------------------------ */

#define IOCTL_MYDRV_TERMINATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MYDRV_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MYDRV_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

DRIVER_INITIALIZE                  DriverEntry;
EVT_WDF_DRIVER_UNLOAD              EvtDriverUnload;
EVT_WDF_DEVICE_FILE_CREATE         EvtDeviceFileCreate;
EVT_WDF_FILE_CLOSE                 EvtFileClose;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

static NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver);

static NTSTATUS do_terminate(_In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ ULONG_PTR* Information);

static NTSTATUS do_read(_In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ ULONG_PTR* Information);

static NTSTATUS do_write(_In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ ULONG_PTR* Information);

/* ------------------------------------------------------------------ */
/* DriverEntry                                                         */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS          status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER         driver;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);   /* no AddDevice */
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("MyKmdfDriver: WdfDriverCreate failed 0x%08X\n", status));
        return status;
    }

    status = CreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("MyKmdfDriver: CreateControlDevice failed 0x%08X\n", status));
        return status;
    }

    KdPrint(("MyKmdfDriver: loaded\n"));
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Control device creation                                             */
/* ------------------------------------------------------------------ */

static NTSTATUS
CreateControlDevice(
    _In_ WDFDRIVER Driver
)
{
    NTSTATUS              status;
    PWDFDEVICE_INIT       deviceInit = NULL;
    WDFDEVICE             controlDevice = NULL;
    WDFQUEUE              queue;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_IO_QUEUE_CONFIG   queueConfig;

    DECLARE_CONST_UNICODE_STRING(deviceName, DEVICE_NAME_W);
    DECLARE_CONST_UNICODE_STRING(symlinkName, SYMLINK_NAME_W);

    /* SYSTEM and Administrators only (same string as SDDL_DEVOBJ_SYS_ALL_ADM_ALL) */
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    deviceInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* Equivalent of IRP_MJ_CREATE / IRP_MJ_CLOSE handling */
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig,
        EvtDeviceFileCreate,
        EvtFileClose,
        WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    /* Run callbacks at PASSIVE_LEVEL so pageable code and PAGED_CODE() are safe */
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;

    /* On success the framework takes ownership of deviceInit and sets it to NULL */
    status = WdfDeviceCreate(&deviceInit, &attributes, &controlDevice);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = WdfDeviceCreateSymbolicLink(controlDevice, &symlinkName);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* Equivalent of the IRP_MJ_DEVICE_CONTROL dispatch routine */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(controlDevice,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    WdfControlFinishInitializing(controlDevice);
    return STATUS_SUCCESS;

Cleanup:
    if (deviceInit != NULL) {
        WdfDeviceInitFree(deviceInit);
    }
    if (controlDevice != NULL) {
        WdfObjectDelete(controlDevice);
    }
    return status;
}

/* ------------------------------------------------------------------ */
/* EvtDriverUnload                                                     */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
VOID
EvtDriverUnload(
    WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    /*
     * Nothing to free: for a non-PnP driver the framework deletes the control
     * device (and its symbolic link) when the driver unloads.
     */
    KdPrint(("MyKmdfDriver: unloaded\n"));
}

/* ------------------------------------------------------------------ */
/* Create / Close                                                      */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
VOID
EvtDeviceFileCreate(
    WDFDEVICE     Device,
    WDFREQUEST    Request,
    WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);

    PAGED_CODE();

    /* TODO: per-handle setup / access checks go here */
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_
VOID
EvtFileClose(
    WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(FileObject);

    PAGED_CODE();

    /* TODO: free anything allocated in EvtDeviceFileCreate */
}

/* ------------------------------------------------------------------ */
/* IOCTL dispatch                                                      */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
VOID
EvtIoDeviceControl(
    WDFQUEUE   Queue,
    WDFREQUEST Request,
    size_t     OutputBufferLength,
    size_t     InputBufferLength,
    ULONG      IoControlCode
)
{
    NTSTATUS  status;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(Queue);

    PAGED_CODE();

    switch (IoControlCode) {

    case IOCTL_MYDRV_TERMINATE:
        status = do_terminate(Request, InputBufferLength, OutputBufferLength, &information);
        break;

    case IOCTL_MYDRV_READ:
        status = do_read(Request, InputBufferLength, OutputBufferLength, &information);
        break;

    case IOCTL_MYDRV_WRITE:
        status = do_write(Request, InputBufferLength, OutputBufferLength, &information);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, information);
}

/* ------------------------------------------------------------------ */
/* IOCTL handlers (stubs)                                              */
/*                                                                     */
/* Get the buffers with WdfRequestRetrieveInputBuffer() and            */
/* WdfRequestRetrieveOutputBuffer(); both take a minimum required      */
/* length and fail with STATUS_BUFFER_TOO_SMALL if the caller's        */
/* buffer is shorter. Set *Information to the number of bytes written  */
/* to the output buffer.                                               */
/* ------------------------------------------------------------------ */

static NTSTATUS
do_terminate(
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ ULONG_PTR* Information
)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PAGED_CODE();

    /* TODO: implement */

    *Information = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS
do_read(
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ ULONG_PTR* Information
)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PAGED_CODE();

    /* TODO: implement (output buffer via WdfRequestRetrieveOutputBuffer) */

    *Information = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS
do_write(
    _In_  WDFREQUEST Request,
    _In_  size_t     InputBufferLength,
    _In_  size_t     OutputBufferLength,
    _Out_ ULONG_PTR* Information
)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PAGED_CODE();

    /* TODO: implement (input buffer via WdfRequestRetrieveInputBuffer) */

    *Information = 0;
    return STATUS_SUCCESS;
}

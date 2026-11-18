/*
* DVWD_KMDF.c
*
* Intentionally vulnerable Windows Kernel-Mode Driver Framework (KMDF) driver.
*
*/

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>

/*
 * Device and symbolink link names
 */
#define DEVICE_NAME_W	L"\\Device\\DVWD_KMDF"
#define SYMLINK_NAME_W	L"\\??\\DVWD_KMDF"


/*
 * IOCTL codes 
 */
#define IOCTL_DVWD_TERMINATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DVWD_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_DVWD_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)


DRIVER_INITIALIZE                  DriverEntry;
EVT_WDF_DRIVER_UNLOAD              EvtDriverUnload;
EVT_WDF_DEVICE_FILE_CREATE         EvtDeviceFileCreate;
EVT_WDF_FILE_CLOSE                 EvtFileClose;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;


static NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver);
static NTSTATUS do_terminate(_In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ ULONG_PTR* Information);
static NTSTATUS do_read(_In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ ULONG_PTR* Information);
static NTSTATUS do_write(_In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ ULONG_PTR* Information);


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS          status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER         driver;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DVWD_KMDF: WdfDriverCreate failed 0x%08X\n", status));
        return status;
    }

    status = CreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DVWD_KMDF: CreateControlDevice failed 0x%08X\n", status));
        return status;
    }

    KdPrint(("DVWD_KMDF: loaded\n"));
    return STATUS_SUCCESS;
}

/* 
 * Control device creation
 */
static NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver)
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

    /*
     * VULNERABILITY:
     *
     * WdfControlDeviceInitAllocate() applies to the future device object the overly-permissive security descriptor
     * identified by SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX. This allows any unprivileged user to interact with 
     * the device driver and send IOCTLs.
     */
    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX);
    if (deviceInit == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    /* Equivalent of IRP_MJ_CREATE / IRP_MJ_CLOSE handling */
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, EvtDeviceFileCreate, EvtFileClose, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    /* Run callbacks at PASSIVE_LEVEL so pageable code and PAGED_CODE() are safe */
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;

    /* On success the framework takes ownership of deviceInit and sets it to NULL */
    status = WdfDeviceCreate(&deviceInit, &attributes, &controlDevice);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    status = WdfDeviceCreateSymbolicLink(controlDevice, &symlinkName);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    /* Equivalent of the IRP_MJ_DEVICE_CONTROL dispatch routine */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(controlDevice,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    WdfControlFinishInitializing(controlDevice);
    return STATUS_SUCCESS;

Cleanup:
    if (deviceInit != NULL)
        WdfDeviceInitFree(deviceInit);
    if (controlDevice != NULL)
        WdfObjectDelete(controlDevice);

    return status;
}


VOID EvtDriverUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    /*
     * Nothing to free: for a non-PnP driver the framework deletes the control
     * device (and its symbolic link) when the driver unloads.
     */
    KdPrint(("MyKmdfDriver: unloaded\n"));
}


VOID EvtDeviceFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);

    PAGED_CODE();

    /* TODO: per-handle setup / access checks go here */

    WdfRequestComplete(Request, STATUS_SUCCESS);
}


VOID EvtFileClose(WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(FileObject);

    PAGED_CODE();

    /* TODO: free anything allocated in EvtDeviceFileCreate */
}


/* 
 * IOCTL dispatch handler
 */
VOID EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    NTSTATUS  status;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(Queue);

    switch (IoControlCode) {
        case IOCTL_DVWD_TERMINATE:
            status = do_terminate(Request, InputBufferLength, OutputBufferLength, &information);
            break;

        case IOCTL_DVWD_READ:
            status = do_read(Request, InputBufferLength, OutputBufferLength, &information);
            break;

        case IOCTL_DVWD_WRITE:
            status = do_write(Request, InputBufferLength, OutputBufferLength, &information);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, information);
}

/* 
 * IOCTL handlers
 */                                                                     
static NTSTATUS do_terminate(_In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ ULONG_PTR* Information)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *Information = 0;

    PVOID           buffer = NULL;
    size_t          length = 0;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, 4, &buffer, &length);
    if (!NT_SUCCESS(status))
        return status;

    if (length!= 4 || buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    UINT32 pid = *((PUINT32) buffer);
    
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);

    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = (HANDLE)0;

    /*
     * VULNERABILITY:
     *
     * ZwOpenProcess() and ZwTerminateProcess() open a handle to and terminate an arbitrary process.
     * This bypasses kernel process protections, such as the protected (PPL) status of security tool processes.
     */
    HANDLE process_handle;
    status = ZwOpenProcess(&process_handle, DELETE, &obj_attr, &cid);
    if (status != STATUS_SUCCESS)
        KdPrint(("DVWD_KMDF: failure accessing proccess %u to terminate: %ul", pid, status));
    else {
        status = ZwTerminateProcess(process_handle, STATUS_SUCCESS);
        if (status != STATUS_SUCCESS)
            KdPrint(("DVWD_KMDF: failure terminating process %u: %ul", pid, status));
    }

    return status;
}


static NTSTATUS do_read(_In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ ULONG_PTR* Information)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    /* TODO: implement (output buffer via WdfRequestRetrieveOutputBuffer) */

    *Information = 0;
    return STATUS_SUCCESS;
}


static NTSTATUS do_write(_In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ ULONG_PTR* Information)
{
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    /* TODO: implement (input buffer via WdfRequestRetrieveInputBuffer) */

    *Information = 0;
    return STATUS_SUCCESS;
}

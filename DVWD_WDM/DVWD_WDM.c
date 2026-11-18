/*
* DVWD_WDM.c
*
* Intentionally vulnerable Windows Driver Model (WDM) driver.
*
*/

#include <ntddk.h>

#define DEVICE_NAME_W	L"\\Device\\DVWD_WDM"
#define SYMLINK_NAME_W	L"\\??\\DVWD_WDM"

/*
* IOCTL codes
*/

#define IOCTL_DVWD_TERMINATE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DVWD_READ \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_DVWD_WRITE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)


DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DispatchCreateClose;
DRIVER_DISPATCH DispatchDeviceControl;

static NTSTATUS dvwd_do_terminate(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp, _Out_ ULONG_PTR* Information);
static NTSTATUS dvwd_do_read(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp, _Out_ ULONG_PTR* Information);
static NTSTATUS dvwd_do_write(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp, _Out_ ULONG_PTR* Information);


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName;
	UNICODE_STRING symlinkName;

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&deviceName, DEVICE_NAME_W);
	RtlInitUnicodeString(&symlinkName, SYMLINK_NAME_W);

	/*
	* VULNERABILITY:
	*
	* Creates the device driver symlink without specifying a restrictive security descriptor using
	* IoCreateDeviceSecure(). This means that any unprivileged user can interact with the device driver
	* and send IOCTLs.
	*/
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
		                    &deviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("DVWD_MDW: IoCreateDevice failed 0x%08X\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symlinkName, &deviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("DVWD_MDW: IoCreateSymbolicLink failed 0x%08X\n", status));
		IoDeleteDevice(deviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	KdPrint(("DVWD_MDW: loaded"));

	return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symlinkName;

	RtlInitUnicodeString(&symlinkName, SYMLINK_NAME_W);
	IoDeleteSymbolicLink(&symlinkName);

	if (DriverObject->DeviceObject != NULL)
		IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint(("DVWD_WDM: unloaded"));
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	NTSTATUS status;
	ULONG_PTR information = 0;
	PIO_STACK_LOCATION irpSp;

	UNREFERENCED_PARAMETER(DeviceObject);

	irpSp = IoGetCurrentIrpStackLocation(Irp);

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DVWD_TERMINATE:
		status = dvwd_do_terminate(Irp, irpSp, &information);
		break;
	case IOCTL_DVWD_READ:
		status = dvwd_do_read(Irp, irpSp, &information);
		break;
	case IOCTL_DVWD_WRITE:
		status = dvwd_do_write(Irp, irpSp, &information);
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

static NTSTATUS dvwd_do_terminate(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp, _Out_ ULONG_PTR* Information)
{
	ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	PVOID buf = Irp->AssociatedIrp.SystemBuffer;

	*Information = 0;

	if (inLen != 4 || buf == NULL)
		return STATUS_INVALID_PARAMETER;

	UINT32 pid = *((PUINT32) buf);

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE process_handle;

	OBJECT_ATTRIBUTES obj_attr;
	InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);

	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE) pid;
	cid.UniqueThread = (HANDLE) 0;

	status = ZwOpenProcess(&process_handle, DELETE, &obj_attr, &cid);
	if (status != STATUS_SUCCESS)
		KdPrint(("DVWD_WDM: failure accessing proccess %u to terminate: %ul", pid, status));
	else {
		status = ZwTerminateProcess(process_handle, STATUS_SUCCESS);
		if (status != STATUS_SUCCESS)
			KdPrint(("DVWD_WDM: failure terminating process %u: %ul", pid, status));
	}

	return status;
}

static NTSTATUS dvwd_do_read(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp, _Out_ ULONG_PTR* Information)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(IrpSp);

	*Information = 0;
	return STATUS_SUCCESS;
}

static NTSTATUS dvwd_do_write(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp, _Out_ ULONG_PTR* Information)
{
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(IrpSp);

	*Information = 0;
	return STATUS_SUCCESS;
}
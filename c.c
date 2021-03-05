#define DBG 1
#include <ntddk.h>
#include <ntifs.h>
#include <ntdef.h>
#include <wdm.h>
#include<ntstatus.h >
#include "h.h"
PDEVICE_OBJECT g_Cdo;

PDRIVER_OBJECT g_MyDriver;

NTSTATUS readFile(HANDLE hFile,
    ULONG offsetLow,
    ULONG offsetHig,
    ULONG sizeToRead,
    PVOID pBuff,
    ULONG* read)
{
    NTSTATUS status;
    IO_STATUS_BLOCK isb = { 0 };
    LARGE_INTEGER offset;
    offset.HighPart = offsetHig;
    offset.LowPart = offsetLow;
    status = ZwReadFile(hFile,/*文件句柄*/
        NULL,/*事件对象,用于异步IO*/
        NULL,/*APC的完成通知例程:用于异步IO*/
        NULL,/*完成通知例程序的附加参数*/
        &isb,/*IO状态*/
        pBuff,/*保存文件数据的缓冲区*/
        sizeToRead,/*要读取的字节数*/
        &offset,/*要读取的文件位置*/
        NULL);
    if (status == STATUS_SUCCESS)
        *read = isb.Information;
    return status;
}
IO_STATUS_BLOCK createFile(wchar_t* filepath,/*文件路径*/
    ULONG access, /*访问权限,: GENERIC_READ, GENERIC_XXX*/
    ULONG share,/*文件共享方式: FILE_SHARE_XXX*/
    ULONG openModel,/* 打开方式: FILE_OPEN_IF,FILE_CREATE ...*/
    BOOLEAN isDir,/*是否为目录*/
    HANDLE* hFile/*成功打开的文件句柄*/)
{
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK StatusBlock = { 0 };
    ULONG           ulShareAccess = share;
    ULONG ulCreateOpt = FILE_SYNCHRONOUS_IO_NONALERT; //同步
    UNICODE_STRING path;
    RtlInitUnicodeString(&path, filepath);
    // 1. 初始化OBJECT_ATTRIBUTES的内容
    OBJECT_ATTRIBUTES objAttrib = { 0 };
    ULONG ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK/*不区分大小写*/;
    InitializeObjectAttributes(&objAttrib,    // 返回初始化完毕的结构体
        &path,      // 文件对象名称
        ulAttributes,  // 对象属性
        NULL, NULL);   // 一般为NULL
    // 2. 创建文件对象
    ulCreateOpt |= isDir ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE;
    status = ZwCreateFile(hFile,                 // 返回文件句柄
        access,                   // 文件操作描述
        &objAttrib,            // OBJECT_ATTRIBUTES
        &StatusBlock,          // 接受函数的操作结果
        0,                     // 初始文件大小
        FILE_ATTRIBUTE_NORMAL, // 新建文件的属性
        ulShareAccess,         // 文件共享方式
        openModel,               // //打开方式
        ulCreateOpt,           // 打开操作的附加标志位
        NULL,                  // 扩展属性区
        0);                    // 扩展属性区长度
    return StatusBlock;
}
IO_STATUS_BLOCK createFile2(wchar_t* filepath,/*文件路径*/
    ULONG access, /*访问权限,: GENERIC_READ, GENERIC_XXX*/
    ULONG share,/*文件共享方式: FILE_SHARE_XXX*/
    ULONG openModel,/* 打开方式: FILE_OPEN_IF,FILE_CREATE ...*/
    BOOLEAN isDir,/*是否为目录*/
    HANDLE* hFile/*成功打开的文件句柄*/)
{
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK StatusBlock = { 0 };
    ULONG           ulShareAccess = share;
    ULONG ulCreateOpt = FILE_SYNCHRONOUS_IO_NONALERT; //同步
    UNICODE_STRING path;
    RtlInitUnicodeString(&path, filepath);
    // 1. 初始化OBJECT_ATTRIBUTES的内容
    OBJECT_ATTRIBUTES objAttrib = { 0 };
    ULONG ulAttributes = OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE|OBJ_FORCE_ACCESS_CHECK    /*不区分大小写*/;
    InitializeObjectAttributes(&objAttrib,    // 返回初始化完毕的结构体
        &path,      // 文件对象名称
        ulAttributes,  // 对象属性
        NULL, NULL);   // 一般为NULL
    // 2. 创建文件对象
    ulCreateOpt |= isDir ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE;
    status = ZwCreateFile(hFile,                 // 返回文件句柄
        access,                   // 文件操作描述
        &objAttrib,            // OBJECT_ATTRIBUTES
        &StatusBlock,          // 接受函数的操作结果
        0,                     // 初始文件大小
        FILE_ATTRIBUTE_NORMAL, // 新建文件的属性
        ulShareAccess,         // 文件共享方式
        openModel,               // //打开方式
        ulCreateOpt,           // 打开操作的附加标志位
        NULL,                  // 扩展属性区
        0);                    // 扩展属性区长度
    return StatusBlock;
}


NTSTATUS
DriverEntry(
    __in struct _DRIVER_OBJECT* DriverObject,
    __in PUNICODE_STRING  RegistryPath
)
{
    int i = 0;
    UNICODE_STRING DeviceName;
    NTSTATUS Status;

    // KdPrintThisFunction();

    g_MyDriver = DriverObject;

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = FsfPassThrough;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FsfCreate;
    DriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] = FsfCreate;
    DriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] = FsfCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = FsfRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = FsfWrite;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = FsfFsControl;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = FsfCleanupClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FsfCleanupClose;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = FsfCleanupClose;

    DriverObject->FastIoDispatch = (PFAST_IO_DISPATCH)ExAllocatePool(NonPagedPool, sizeof(FAST_IO_DISPATCH));
    if (DriverObject->FastIoDispatch == NULL) {
        //  KdPrint((FSF_MODULE_NAME_PREFIX "Allocate fast io dispatch rotine memory failed.\n"));
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    RtlZeroMemory(DriverObject->FastIoDispatch, sizeof(FAST_IO_DISPATCH));

    DriverObject->FastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
    DriverObject->FastIoDispatch->FastIoCheckIfPossible = FsfFastIoCheckIfPossible;
    DriverObject->FastIoDispatch->FastIoRead = FsfFastIoRead;
    DriverObject->FastIoDispatch->FastIoWrite = FsfFastIoWrite;
    DriverObject->FastIoDispatch->FastIoQueryBasicInfo = FsfFastIoQueryBasicInfo;
    DriverObject->FastIoDispatch->FastIoQueryStandardInfo = FsfFastIoQueryStandardInfo;
    DriverObject->FastIoDispatch->FastIoLock = FsfFastIoLock;
    DriverObject->FastIoDispatch->FastIoUnlockSingle = FsfFastIoUnlockSingle;
    DriverObject->FastIoDispatch->FastIoUnlockAll = FsfFastIoUnlockAll;
    DriverObject->FastIoDispatch->FastIoUnlockAllByKey = FsfFastIoUnlockAllByKey;
    DriverObject->FastIoDispatch->FastIoDeviceControl = FsfFastIoDeviceControl;
    DriverObject->FastIoDispatch->FastIoDetachDevice = FsfFastIoDetachDevice;
    DriverObject->FastIoDispatch->FastIoQueryNetworkOpenInfo = FsfFastIoQueryNetworkOpenInfo;
    DriverObject->FastIoDispatch->MdlRead = FsfFastIoMdlRead;
    DriverObject->FastIoDispatch->MdlReadComplete = FsfFastIoMdlReadComplete;
    DriverObject->FastIoDispatch->PrepareMdlWrite = FsfFastIoPrepareMdlWrite;
    DriverObject->FastIoDispatch->MdlWriteComplete = FsfFastIoWriteComplete;
    DriverObject->FastIoDispatch->FastIoReadCompressed = FsfFastIoReadCompressed;
    DriverObject->FastIoDispatch->FastIoWriteCompressed = FsfFastIoWriteCompressed;
    DriverObject->FastIoDispatch->MdlReadCompleteCompressed = FsfFastIoReadCompleteCompressed;
    DriverObject->FastIoDispatch->MdlWriteCompleteCompressed = FsfFastIoWriteCompleteCompressed;
    DriverObject->FastIoDispatch->FastIoQueryOpen = FsfFastIoQueryOpen;

    DriverObject->DriverUnload = FsfUnload;

    // 生成一个控制设备 CDO
    RtlInitUnicodeString(&DeviceName, L"\\FileSystem\\Filters\\FsFilter");
    Status = IoCreateDevice(DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_DISK_FILE_SYSTEM,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_Cdo);
    if (!NT_SUCCESS(Status)) {
        //KdPrint((FSF_MODULE_NAME_PREFIX "Create the device failed.\n"));
        goto Fail;
    }

    // 设置文件系统加载和注销回调
    Status = IoRegisterFsRegistrationChange(DriverObject, FsfFsNotification);
    if (!NT_SUCCESS(Status)) {
        //  KdPrint((FSF_MODULE_NAME_PREFIX "Register file system chang notification failed!\n"));
        goto Fail;
    }

    return STATUS_SUCCESS;

Fail:
    if (DriverObject->FastIoDispatch != NULL) {
        ExFreePool(DriverObject->FastIoDispatch);
    }

    if (g_Cdo != NULL) {
        IoDeleteDevice(g_Cdo);
    }

    return Status;
}

NTSTATUS
FsfPassThrough(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    PFSF_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}

VOID
FsfUnload(
    __in struct _DRIVER_OBJECT* DriverObject
)
{
    PDEVICE_OBJECT MyDevice;

    // KdPrintThisFunction();

    IoUnregisterFsRegistrationChange(DriverObject, FsfFsNotification);

    MyDevice = DriverObject->DeviceObject;
    while (MyDevice != NULL) {
        PDEVICE_OBJECT TempDevice = MyDevice->NextDevice;

        // 如果是不是我的控制设备，则面要解除附加
        if (!IsMyControlDeivce(MyDevice)) {
            // 如果是文件系统控制设备的过滤设备或文件系统卷设备的过滤设备
            if (IsMyFilterDevice(MyDevice)) {
                PFSF_DEVICE_EXTENSION DeviceExtension = MyDevice->DeviceExtension;
                IoDetachDevice(DeviceExtension->AttachedToDeviceObject);
                //KdPrintWithFuncPrefix("Deattach the fs cdo or volime filter.\n");
            }
        }

        IoDeleteDevice(MyDevice);
        MyDevice = TempDevice;
    }

}

NTSTATUS
FsfReadCompletion(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in_xcount_opt("varies") PVOID Context
)
{
    PKEVENT WaitEvent = Context;

    KeSetEvent(WaitEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}
BOOLEAN GetPathByFileObject(PFILE_OBJECT FileObject, WCHAR* wzPath)
{
    BOOLEAN bGetPath = FALSE;
    CHAR szIoQueryFileDosDeviceName[] = "IoQueryFileDosDeviceName";
    CHAR szIoVolumeDeviceToDosName[] = "IoVolumeDeviceToDosName";
    CHAR szRtlVolumeDeviceToDosName[] = "RtlVolumeDeviceToDosName";

    POBJECT_NAME_INFORMATION ObjectNameInformation = NULL;
    __try
    {
        if (FileObject && MmIsAddressValid(FileObject) && wzPath)
        {

            if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &ObjectNameInformation)))   //注意该函数调用后要释放内存
            {
                wcsncpy(wzPath, ObjectNameInformation->Name.Buffer, ObjectNameInformation->Name.Length);

                bGetPath = TRUE;

                ExFreePool(ObjectNameInformation);
            }


            if (!bGetPath)
            {

                if (IoVolumeDeviceToDosName || RtlVolumeDeviceToDosName)
                {
                    NTSTATUS  Status = STATUS_UNSUCCESSFUL;
                    ULONG_PTR ulRet = 0;
                    PVOID     Buffer = ExAllocatePool(PagedPool, 0x1000);

                    if (Buffer)
                    {
                        // ObQueryNameString : \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareTray.exe
                        memset(Buffer, 0, 0x1000);
                        Status = ObQueryNameString(FileObject, (POBJECT_NAME_INFORMATION)Buffer, 0x1000, &ulRet);
                        if (NT_SUCCESS(Status))
                        {
                            POBJECT_NAME_INFORMATION Temp = (POBJECT_NAME_INFORMATION)Buffer;

                            WCHAR szHarddiskVolume[100] = L"\\Device\\HarddiskVolume";

                            if (Temp->Name.Buffer != NULL)
                            {
                                if (Temp->Name.Length / sizeof(WCHAR) > wcslen(szHarddiskVolume) &&
                                    !_wcsnicmp(Temp->Name.Buffer, szHarddiskVolume, wcslen(szHarddiskVolume)))
                                {
                                    // 如果是以 "\\Device\\HarddiskVolume" 这样的形式存在的，那么再查询其卷名。
                                    UNICODE_STRING uniDosName;

                                    if (NT_SUCCESS(IoVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName)))
                                    {
                                        if (uniDosName.Buffer != NULL)
                                        {

                                            wcsncpy(wzPath, uniDosName.Buffer, uniDosName.Length);
                                            wcsncat(wzPath, Temp->Name.Buffer + wcslen(szHarddiskVolume) + 1, Temp->Name.Length - (wcslen(szHarddiskVolume) + 1));
                                            bGetPath = TRUE;
                                        }

                                        ExFreePool(uniDosName.Buffer);
                                    }

                                    else if (NT_SUCCESS(RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName)))
                                    {
                                        if (uniDosName.Buffer != NULL)
                                        {

                                            wcsncpy(wzPath, uniDosName.Buffer, uniDosName.Length);
                                            wcsncat(wzPath, Temp->Name.Buffer + wcslen(szHarddiskVolume) + 1, Temp->Name.Length - (wcslen(szHarddiskVolume) + 1));
                                            bGetPath = TRUE;
                                        }

                                        ExFreePool(uniDosName.Buffer);
                                    }

                                }
                                else
                                {
                                    // 如果不是以 "\\Device\\HarddiskVolume" 这样的形式开头的，那么直接复制名称。

                                    wcsncpy(wzPath, Temp->Name.Buffer, Temp->Name.Length);
                                    bGetPath = TRUE;
                                }
                            }
                        }

                        ExFreePool(Buffer);
                    }
                }
            }
        }
    }
    __except (1)
    {
        DbgPrint("GetPathByFileObject Catch __Except\r\n");
        bGetPath = FALSE;
    }

    return bGetPath;

}
ULONG openif = 0;

//防止我自己过滤自己- -
INT save = 1;
INT save3 = 1;
INT savecolse = 1;
INT save4 = 1;
BOOLEAN  ifpass(ACCESS_MASK DesiredAccess) {
    //文件请求的访问属性
    //文件请求的标准访问权限
    ULONG GDesiredAccess = DesiredAccess & 0xff000000;
    //文件请求的SACL访问权限
    ULONG SDesiredAccess = (DesiredAccess - GDesiredAccess) & 0xff0000;
    // 文件请求的对特定对象的访问权限
    ULONG ODesiredAccess = DesiredAccess - GDesiredAccess - SDesiredAccess;
    //如果是在用户下
    //并且我们还需要检查的请求权限是否有写入权限或者更改控制权限
    //如果只能读取文件并且只能打开存在的文件对我们毫无用处
    if (  DesiredAccess&&
        ODesiredAccess != FILE_READ_DATA
        && ODesiredAccess != FILE_READ_DATA | FILE_READ_ATTRIBUTES
        && ODesiredAccess != FILE_READ_DATA | FILE_READ_EA
        && ODesiredAccess != FILE_READ_ATTRIBUTES
        && ODesiredAccess != FILE_READ_EA
        && ODesiredAccess != FILE_READ_EA | FILE_READ_ATTRIBUTES
        && (GDesiredAccess != GENERIC_READ
           || GDesiredAccess == MAXIMUM_ALLOWED)
       /// 排除只能读取文件并且只能打开存在的文件
        && (SDesiredAccess != SYNCHRONIZE && SDesiredAccess != READ_CONTROL && SDesiredAccess != (READ_CONTROL | SYNCHRONIZE)) )
    {
        return  1;
    }
    return  0;
}
INT init = 0;
INT ifsave = 0;

SECURITY_SUBJECT_CONTEXT ssc2 = {0};
SECURITY_SUBJECT_CONTEXT ssc3 = { 0 };
PRIVILEGE_SET Privilegesl = { 0 };
NTSTATUS
FsfCreate(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    BOOLEAN Present = NULL;
    PBOOLEAN  DaclDefaulted = NULL;
    BOOLEAN  OwnerDefaulted = NULL;
    UNICODE_STRING Username = { 0 };
    PULONG  idsize = 16;
    PSID_NAME_USE SidType = SidTypeUser;
    PFSF_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    KEVENT WaitEvent;
    NTSTATUS Status;
    BOOLEAN SdAllocated = 0;
    SECURITY_SUBJECT_CONTEXT  SubjectSecurityContext = IoStackLocation->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext;
    PEPROCESS  PROCESS;
    POBJECT_NAME_INFORMATION NameInfo;
    ULONG ReturnLength = 0;
    SECURITY_SUBJECT_CONTEXT ssc;
    PACCESS_TOKEN at;
    PIO_SECURITY_CONTEXT ISC = (DWORD64)IoStackLocation + 0x8;
    NTSTATUS status;
    SECURITY_IMPERSONATION_LEVEL   tksl;
    PBOOLEAN  DaclPresent = 0;
    ULONG tempfile = 0;
    BOOLEAN                   SubjectContextLocked = 1;
    ACCESS_MASK               PreviouslyGrantedAccess = 0;
    PGENERIC_MAPPING          GenericMapping = 0;
    ACCESS_MASK              GrantedAccess = 0;
    NTSTATUS                 AccessStatus = 0;
    // 如果是我的控制设备，则直接完成
    if (IsMyControlDeivce(DeviceObject)) {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    // 如果是我的文件系统控制设备的过滤设备(控制设备过滤设备没有保存存储卷设备)，则直接下发
    if (DeviceExtension == NULL) {
        return FsfPassThrough(DeviceObject, Irp);
    }

    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, FsfReadCompletion, &WaitEvent, TRUE, TRUE, TRUE);
    Status = IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, FALSE);
    }
    CHAR* PROC = PsGetCurrentProcess();
    CHAR* NAME = PROC + 0x450;
    if (!strcmp(NAME, "test.exe")&&!init)
    {  //获取当前线程上下文
        SeCaptureSubjectContext(&ssc);
        //锁定当前上下文
        SeLockSubjectContext(&ssc);
        ssc2 = ssc;
        ssc3 = ssc;
        init = 1;
        SeUnlockSubjectContext(&ssc);
        SeReleaseSubjectContext(&ssc);
    }/*
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;*/
    if (!init)
    {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
    }
    ULONG Mode = Irp->RequestorMode;
    if (!strcmp(NAME, "mscorsvw.exe")
        || !strcmp(NAME, "svchost.exe")
        || !strcmp(NAME, "ngen.exe")
        || !strcmp(NAME, "MsMpEng.exe")
        || !strcmp(NAME, "sppsvc.exe")
        || !strcmp(NAME, "System")
        || !strcmp(NAME, "wermgr.exe")
        || !strcmp(NAME, "TiWorker.exe")
        || !strcmp(NAME, "sedsvc.exe")
        || !strcmp(NAME, "wuauclt.exe")
        || !strcmp(NAME, "explorer.exe")
        || !strcmp(NAME, "spoolsv.exe")
        )
    {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
    }

    DWORD64 IntegrityLevel = 0;
    PWSTR Buffer = ExAllocatePoolWithTag(1, 0x500, 8);
   // //1709 x64下的进程名偏移
   // //是否排除一些系统进程 可以选择注释
   // //共享属性
    ULONG ShareAccess = IoStackLocation->Parameters.Create.ShareAccess;
    //文件属性
    ULONG Flage = IoStackLocation->Flags;
    //调用模式
   // ULONG Mode = Irp->RequestorMode;
    //文件创建时的标志  比如FILE_CREATE 
    ULONG CreateDisposition = IoStackLocation->Parameters.Create.Options / 0x1000000;
    //文件创建时的附加标志  比如FILE_SYNCHRONOUS_IO_NONALERT  
    ULONG CreateDisposition2 = IoStackLocation->Parameters.Create.Options - CreateDisposition * 0x1000000;
    //是否允许创建不允许的文件
    ULONG createflag = 0;
    switch (CreateDisposition)
    {
    case FILE_SUPERSEDE:
        createflag = 1;
        break;
    case FILE_OPEN:
        break;
    case FILE_CREATE:
        createflag = 1;
        break;
    case FILE_OPEN_IF:
        createflag = 1;
        break;
    case FILE_OVERWRITE:
        break;
    case FILE_OVERWRITE_IF:
        createflag = 1;
        break;
    }
    //是否打开的是解析文件
    INT REPARSE = 0;
    if (CreateDisposition2 >= FILE_OPEN_REPARSE_POINT &&
        (CreateDisposition2 / FILE_OPEN_REPARSE_POINT) % 2 == 1)
    {
        REPARSE = 1;
    }
    //是否打开的文件是否允许上锁
    ULONG oplock = 0;
    if (CreateDisposition2 >= FILE_OPEN_REQUIRING_OPLOCK &&
        (CreateDisposition2 / FILE_OPEN_REQUIRING_OPLOCK) % 2 == 1)
    {
        oplock = 1;
    }
    //打开的文件是否是临时文件
    if (CreateDisposition2 >= FILE_DELETE_ON_CLOSE &&
        (CreateDisposition2 / FILE_DELETE_ON_CLOSE) % 2 == 1)
    {
        tempfile = 1;
    }
    //文件请求的访问属性
    ACCESS_MASK    DesiredAccess = IoStackLocation->Parameters.Create.SecurityContext->DesiredAccess;
    //文件请求的标准访问权限
    ULONG GDesiredAccess = DesiredAccess & 0xff000000;
    //文件请求的SACL访问权限
    ULONG SDesiredAccess = (DesiredAccess - GDesiredAccess) & 0xff0000;
    // 文件请求的对特定对象的访问权限  在内核下我们不需要关注这个
    ULONG ODesiredAccess = DesiredAccess - GDesiredAccess - SDesiredAccess;
    //如果是在驱动中打开的文件
    //我们需要关注没有设置OBJ_FORCE_ACCESS_CHECK上标志
    //我们还需要关注有没有设置SL_STOP_ON_SYMLINK标志 检查打开的是否是符号链接
    //并且我们还需要检查的请求权限是否有写入权限或者更改控制权限
    //如果只能读取文件并且只能打开存在的文件对我们毫无用处
   if (Mode == KernelMode&& save3
       //OBJ_FORCE_ACCESS_CHECK排除检查内核句柄
       && Flage % 2 != SL_FORCE_ACCESS_CHECK
       //SL_STOP_ON_SYMLINK排除检查符号链接
       && ((Flage / 8) % 2 == 0 || Flage == 0)
       //我们不需要只能读取文件
       && (GDesiredAccess != GENERIC_READ
           || GDesiredAccess == MAXIMUM_ALLOWED)
       && ODesiredAccess != FILE_READ_DATA
       && ODesiredAccess != FILE_READ_DATA | FILE_READ_ATTRIBUTES
       && ODesiredAccess != FILE_READ_DATA | FILE_READ_EA
       && ODesiredAccess != FILE_READ_ATTRIBUTES
       && ODesiredAccess != FILE_READ_EA
       && ODesiredAccess != FILE_READ_EA | FILE_READ_ATTRIBUTES
       //排除只能读取文件并且只能打开存在的文件
       && (SDesiredAccess != SYNCHRONIZE && SDesiredAccess != READ_CONTROL && SDesiredAccess != (READ_CONTROL | SYNCHRONIZE) || createflag)
       )
   {
       //获取当前线程上下文
       SeCaptureSubjectContext(&ssc);
       //锁定当前上下文
       SeLockSubjectContext(&ssc);
       at = SeQuerySubjectContextToken(&ssc);
       //判断当前token类型。在这里我们对模拟令牌不感兴趣  
       ULONG STA = SeQueryInformationToken(at, TokenImpersonationLevel, &tksl);
       //如果是模拟令牌我们则不感兴趣
       if (STA == STATUS_SUCCESS)
       {
           //善后
           SeUnlockSubjectContext(&ssc);
           SeReleaseSubjectContext(&ssc);
           IoCompleteRequest(Irp, IO_NO_INCREMENT);
           return Irp->IoStatus.Status;
       }
       //善后
       SeUnlockSubjectContext(&ssc);
       SeReleaseSubjectContext(&ssc);
       //找到漏洞后，我们需要收集一些信息来帮助快速编写利用以及定位漏洞根本成因
       //这些信息包括是否允许创建不存在的文件，进程名 进程id以及目标文件路径 访问权限 是否允许打开上锁的文件等
       //1709 x64下的进程名偏移
       ULONG pid = PsGetProcessId(PROC);
       //pid数字转字符串
       CHAR idstr[6] = { 0 };
       for (int t = 5; t != -1; t--)
       {
           idstr[t] = pid % 10 + '0';
           pid = pid / 10;
       }
       //访问属性数字转字符串
       CHAR dstr[6] = { 0 };
       INT TEMP = DesiredAccess / 0x10000;
       BOOLEAN of = 0;
       //访问属性是否大于0x10000;
       if (TEMP)
       {
           for (int t = 5; t != -1; t--)
           {
               dstr[t] = TEMP % 10 + '0';
               TEMP = TEMP / 10;
           }
       }
       else
       {
           of = 1;
           for (int t = 5; t != -1; t--)
           {
               dstr[t] = ODesiredAccess % 10 + '0';
               ODesiredAccess = ODesiredAccess / 10;
           }
       }
       CHAR buf[500] = { 0 };
       GetPathByFileObject(IoStackLocation->FileObject, Buffer);
       //wchar转char
       if (!wcscmp(Buffer, L"C:") || Buffer[0] == 0)
       {
       }
       else
       {
           for (size_t i = 0; i < wcslen(Buffer); i++)
           {
               if (Buffer[i] != 0)
               {

                   buf[i] = Buffer[i];
               }
           }
           IO_STATUS_BLOCK StatusBlock = { 0 };
           HANDLE filehand = 0;
           PDWORD64 read = NULL;
           //防止自己过滤自己
           if (save3)
           {
               save3 = 0;
               StatusBlock = createFile(L"\\??\\C:\\BoomKernel.txt", GENERIC_ALL, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, 0, &filehand//保存句柄
               );
               save3 = 1;
           }
           INT ret = 0;
           while (ret != STATUS_END_OF_FILE)
           {
               CHAR BUF[1024];
               ret = ZwReadFile(filehand, NULL, NULL, NULL, &StatusBlock, BUF, 1024, NULL, NULL);
           }
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, " boomboomboom!!!\r\n", sizeof(" boomboomboom!!!\r\n"), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   文件名 :", sizeof("   文件名 :"), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, buf, strnlen(buf, 500), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   进程名 :", sizeof("   进程名 :"), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, NAME, strnlen(NAME, 500), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n    进程id :", sizeof("\r\n    进程id :"), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, idstr, 6, NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  访问属性 :", sizeof("  访问属性 :"), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, dstr, 6, NULL, NULL);
           if (!of)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "*0x10000", sizeof("*0x10000"), NULL, NULL);
           if (REPARSE)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  是解析点", sizeof("  是解析点"), NULL, NULL);
           else
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  不是解析点", sizeof("  不是解析点"), NULL, NULL);
           if (createflag)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  可创建不存在的文件", sizeof("  可创建不存在的文件"), NULL, NULL);
           else
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  只能打开现有的文件", sizeof("  只能打开现有的文件"), NULL, NULL);
           if (oplock)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  文件有锁则会失败", sizeof("  文件有锁则会失败"), NULL, NULL);
           else
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  可对目标文件上锁", sizeof("  可对目标文件上锁"), NULL, NULL);
           if (tempfile)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  是临时文件", sizeof("  是临时文件"), NULL, NULL);
           else
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  不是临时文件", sizeof("  不是临时文件"), NULL, NULL);
           if (!ShareAccess)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  不允许共享", sizeof("  不允许共享"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_READ)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享读取", sizeof("  共享读取"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_WRITE)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享写入", sizeof("  共享写入"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_WRITE)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享写入和读取", sizeof("  共享写入"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_DELETE)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享删除", sizeof("  共享删除"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_DELETE | FILE_SHARE_READ)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享删除和读取", sizeof("  共享删除和读取"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_DELETE | FILE_SHARE_WRITE)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享删除和写入", sizeof("  共享删除和写入"), NULL, NULL);
           else if (ShareAccess == FILE_SHARE_VALID_FLAGS)
               ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享所有", sizeof("  共享所有"), NULL, NULL);
           ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n", sizeof("\r\n"), NULL, NULL);
           savecolse = 0;
           ZwClose(filehand);
           savecolse = 1;
       }
   }
   // //我们还需要检查的请求权限是否有写入权限或者更改控制权限
   // //如果只能读取文件并且只能打开存在的文件对我们毫无用处
    if (Mode == 1&&save&&
       ODesiredAccess != FILE_READ_DATA
       && ODesiredAccess != FILE_READ_DATA | FILE_READ_ATTRIBUTES
       && ODesiredAccess != FILE_READ_DATA | FILE_READ_EA
       && ODesiredAccess != FILE_READ_ATTRIBUTES
       && ODesiredAccess != FILE_READ_EA
       && ODesiredAccess != FILE_READ_EA | FILE_READ_ATTRIBUTES
       && (GDesiredAccess != GENERIC_READ
            || GDesiredAccess == MAXIMUM_ALLOWED)
        //我们需要关注有没有设置SL_STOP_ON_SYMLINK标志 检查打开的是否是符号链接并且还是目录 否则无法利用
        && (((IoStackLocation->Flags / SL_STOP_ON_SYMLINK) % 2 ==0 || Flage == 0) && (CreateDisposition2 % 2 != FILE_DIRECTORY_FILE))
        /// 排除只能读取文件并且只能打开存在的文件
        && (SDesiredAccess != SYNCHRONIZE && SDesiredAccess != READ_CONTROL && SDesiredAccess != (READ_CONTROL | SYNCHRONIZE) || createflag)
        //和安全描述符对比的安全上下文初始化完毕
        )
    {
            //获取当前线程上下文
            SeCaptureSubjectContext(&ssc);
            //锁定当前上下文
            SeLockSubjectContext(&ssc);
            //获取token
            at = SeQuerySubjectContextToken(&ssc);
            //判断当前token类型。在这里我们对模拟令牌不感兴趣  
            ULONG ret2 = SeQueryInformationToken(at, TokenImpersonationLevel, &tksl);
            //获取token级别
            SeQueryInformationToken(at, TokenIntegrityLevel, &IntegrityLevel);
            //获取安全描述符
            PSECURITY_DESCRIPTOR     SecurityDescriptor = ExAllocatePoolWithTag(3, sizeof(SECURITY_DESCRIPTOR), 1);
            ObGetObjectSecurity(IoStackLocation->FileObject, &SecurityDescriptor, &DaclDefaulted);
            //检查安全描述符是否有效
            ULONG ret = 0;
            if (Mode == UserMode)
            {
                 ret = RtlValidSecurityDescriptor(SecurityDescriptor);
            }
            else if(Mode== KernelMode)
            {
                 ret = SeValidSecurityDescriptor(sizeof(SECURITY_DESCRIPTOR),SecurityDescriptor);
            }
            SeUnlockSubjectContext(&ssc);
            SeReleaseSubjectContext(&ssc);
            //如果是模拟令牌或者高权限以下或者没有安全描述符以及安全描述符无效我们则不感兴趣
            if (ret2 == STATUS_SUCCESS|| IntegrityLevel <0x3000|| SecurityDescriptor == 0||!ret)
            {

                ExFreePoolWithTag(Buffer, 8);
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return Irp->IoStatus.Status;
            }
            //ssc2是全局上下文变量，也就是测试用例的上下文而不是高权限上下文
            SeLockSubjectContext(&ssc2);
            GENERIC_MAPPING* GenericMapping = (GENERIC_MAPPING*)IoGetFileObjectGenericMapping();
            PPRIVILEGE_SET Privileges = NULL;  
             //判断是否有写入权限
            ULONG ret3 = SeAccessCheck(SecurityDescriptor, &ssc2, SubjectContextLocked, DELETE,
                0, 0, GenericMapping, UserMode, &GrantedAccess, &AccessStatus);
            if (ret3)
            {
                GetPathByFileObject(IoStackLocation->FileObject, Buffer);
                if (!wcscmp(Buffer, L"C:") || Buffer[0] == 0)
                {
                }
                //记录信息
                else
                {
                    DbgPrint("%S\n", Buffer);
                    ULONG pid = PsGetProcessId(PROC);
                    //pid数字转字符串
                    CHAR idstr[6] = { 0 };
                    for (int t = 5; t != -1; t--)
                    {
                        idstr[t] = pid % 10 + '0';
                        pid = pid / 10;
                    }
                    //访问属性数字转字符串
                    CHAR dstr[6] = { 0 };
                    INT TEMP = DesiredAccess / 0x10000;
                    BOOLEAN of = 0;
                    //访问属性是否大于0x10000;
                    if (TEMP)
                    {
                        for (int t = 5; t != -1; t--)
                        {
                            dstr[t] = TEMP % 10 + '0';
                            TEMP = TEMP / 10;
                        }
                    }
                    else
                    {
                        of = 1;
                        for (int t = 5; t != -1; t--)
                        {
                            dstr[t] = ODesiredAccess % 10 + '0';
                            ODesiredAccess = ODesiredAccess / 10;
                        }
                    }
                    CHAR buf[500] = { 0 };
                    //wchar转char
                    for (size_t i = 0; i < wcslen(Buffer); i++)
                    {
                        if (Buffer[i] != 0)
                        {

                            buf[i] = Buffer[i];
                        }
                    }
                    IO_STATUS_BLOCK StatusBlock = { 0 };
                    HANDLE filehand = 0;
                    PDWORD64 read = NULL;
                    if (save)
                    {
                        save = 0;
                        StatusBlock = createFile(L"\\??\\C:\\BoomUsersCreate.txt", GENERIC_ALL, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, 0, &filehand//保存句柄
                        );
                        save = 1;
                    }
                    INT ret = 0;
                    while (ret != STATUS_END_OF_FILE)
                    {
                        CHAR BUF[1024];
                        ret = ZwReadFile(filehand, NULL, NULL, NULL, &StatusBlock, BUF, 1024, NULL, NULL);
                    }
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, " boomboomboom!!!\r\n", sizeof(" boomboomboom!!!\r\n"), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   文件名 :", sizeof("   文件名 :"), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, buf, strnlen(buf, 500), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   进程名 :", sizeof("   进程名 :"), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, NAME, strnlen(NAME, 500), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n    进程id :", sizeof("\r\n    进程id :"), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, idstr, 6, NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  访问属性 :", sizeof("  访问属性 :"), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, dstr, 6, NULL, NULL);
                    if (!of)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "*0x10000", sizeof("*0x10000"), NULL, NULL);
                    if (REPARSE)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  是解析点", sizeof("  是解析点"), NULL, NULL);
                    else
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  不是解析点", sizeof("  不是解析点"), NULL, NULL);
                    if (createflag)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  可创建不存在的文件", sizeof("  可创建不存在的文件"), NULL, NULL);
                    else
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  只能打开现有的文件", sizeof("  只能打开现有的文件"), NULL, NULL);
                    if (oplock)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  文件有锁则会失败", sizeof("  文件有锁则会失败"), NULL, NULL);
                    else
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  可对目标文件上锁", sizeof("  可对目标文件上锁"), NULL, NULL);
                    if (tempfile)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  是临时文件", sizeof("  是临时文件"), NULL, NULL);
                    else
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  不是临时文件", sizeof("  不是临时文件"), NULL, NULL);
                    if (!ShareAccess)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  不允许共享", sizeof("  不允许共享"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_READ)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享读取", sizeof("  共享读取"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_WRITE)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享写入", sizeof("  共享写入"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_WRITE)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享写入和读取", sizeof("  共享写入"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_DELETE)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享删除", sizeof("  共享删除"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_DELETE | FILE_SHARE_READ)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享删除和读取", sizeof("  共享删除和读取"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_DELETE | FILE_SHARE_WRITE)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享删除和写入", sizeof("  共享删除和写入"), NULL, NULL);
                    else if (ShareAccess == FILE_SHARE_VALID_FLAGS)
                        ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "  共享所有", sizeof("  共享所有"), NULL, NULL);
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n", sizeof("\r\n"), NULL, NULL);
                    savecolse = 0;
                    ZwClose(filehand);
                    savecolse = 1;
                }
            }
            SeUnlockSubjectContext(&ssc2);
    }
    ExFreePoolWithTag(Buffer, 8);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

ULONG ReadLength;
NTSTATUS
FsfRead(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    PFSF_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    LARGE_INTEGER Offset;

    // 如果是我的控制设备，则直接完成
    if (IsMyControlDeivce(DeviceObject)) {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        return STATUS_SUCCESS;
    }

    // 如果是我的文件系统控制设备的过滤设备(控制设备过滤设备没有保存存储卷设备)，则直接下发
    if (DeviceExtension == NULL) {
        return FsfPassThrough(DeviceObject, Irp);
    }

    // 下面是对文件系统卷设备的过滤处理
   // Offset.QuadPart = IoStackLocation->Parameters.Read.ByteOffset.QuadPart;
    //保存文件读取长度
   // ReadLength = IoStackLocation->Parameters.Read.Length;
    // KdPrintWithFuncPrefix("Read - ");
    // KdPrint(("Offset (0x%08x, 0x%08x), Length (0x%08x).\n", Offset.HighPart, Offset.LowPart, Length));

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}


WCHAR binkname[500] = { 0 };
NTSTATUS
FsfWrite(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    BOOLEAN Present = NULL;
    PBOOLEAN  DaclDefaulted = NULL;
    BOOLEAN  OwnerDefaulted = NULL;
    UNICODE_STRING Username = { 0 };
    PULONG  idsize = 16;
    PSID_NAME_USE SidType = SidTypeUser;
    PFSF_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    KEVENT WaitEvent;
    NTSTATUS Status;
    BOOLEAN SdAllocated = 0;
    SECURITY_SUBJECT_CONTEXT  SubjectSecurityContext = IoStackLocation->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext;
    PEPROCESS  PROCESS;
    POBJECT_NAME_INFORMATION NameInfo;
    ULONG ReturnLength = 0;
    SECURITY_SUBJECT_CONTEXT ssc;
    PACCESS_TOKEN at;
    PIO_SECURITY_CONTEXT ISC = (DWORD64)IoStackLocation + 0x8;
    NTSTATUS status;
    SECURITY_IMPERSONATION_LEVEL   tksl;
    PBOOLEAN  DaclPresent = 0;
    ULONG tempfile = 0;
    BOOLEAN                   SubjectContextLocked = 1;
    ACCESS_MASK               PreviouslyGrantedAccess = 0;
    PGENERIC_MAPPING          GenericMapping = 0;
    ACCESS_MASK              GrantedAccess = 0;
    NTSTATUS                 AccessStatus = 0;
    LARGE_INTEGER Offset;
    ULONG WriteLength;

    // 如果是我的控制设备，则直接完成
    if (IsMyControlDeivce(DeviceObject)) {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    // 如果是我的文件系统控制设备的过滤设备(控制设备过滤设备没有保存存储卷设备)，则直接下发
    if (DeviceExtension == NULL) {
        return FsfPassThrough(DeviceObject, Irp);
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}

/*
 * 卷挂载完成事件
 * 在这里直接进行绑定有一定的风险，因为此时中断级别很高，是 DISPATCH_LEVEL，
 * 所以进行了推迟绑定，这里只是设置一下事件。
 */
NTSTATUS
FsfMountVolumeCompletion(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in_xcount_opt("varies") PVOID Context
)
{
    PKEVENT WaitEvent = (PKEVENT)Context;

    KeSetEvent(WaitEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;

}

NTSTATUS
FsfControlMountVolume(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    PDEVICE_OBJECT StorageDevice;
    PDEVICE_OBJECT MyDevice;
    NTSTATUS Status;
    PFSF_DEVICE_EXTENSION DeviceExtension;
    ULONG ReturnLength = 0;
    KEVENT CompletionEvent;
    PFSF_DEVICE_EXTENSION MyCdoFilterDeviceExtension = DeviceObject->DeviceExtension;
    char Buff[512];
    POBJECT_NAME_INFORMATION NameInfo;

    // 记录下实际存储媒介设备对象，即磁盘卷设备对象，以便后面可以取回 VPB
    // Vpb->DeviceObject 才是文件系统卷设备, 这是我们需要挂接的设备，在该 IRP 完成后，它就是有意思的对象了
    StorageDevice = IoGetCurrentIrpStackLocation(Irp)->Parameters.MountVolume.Vpb->RealDevice;
    Status = IoCreateDevice(g_MyDriver,
        sizeof(FSF_DEVICE_EXTENSION),
        NULL,
        DeviceObject->DeviceType,
        0,
        FALSE,
        &MyDevice);

    DeviceExtension = MyDevice->DeviceExtension;
    DeviceExtension->StorageDevice = StorageDevice;
    DeviceExtension->TypeFlag = FSF_DEVICE_FLAG;

    // 记录下存储设备的名字
    RtlInitEmptyUnicodeString(&DeviceExtension->AttachedToDeviceName,
        DeviceExtension->AttachedToDeviceNameBuff,
        sizeof(DeviceExtension->AttachedToDeviceNameBuff));
    NameInfo = (POBJECT_NAME_INFORMATION)Buff;
    ObQueryNameString(StorageDevice,
        NameInfo,
        sizeof(Buff),
        &ReturnLength);
    RtlCopyUnicodeString(&DeviceExtension->AttachedToDeviceName, &NameInfo->Name);

    // 调用下层驱动并等待其完成
    KeInitializeEvent(&CompletionEvent, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, FsfMountVolumeCompletion, &CompletionEvent, TRUE, TRUE, TRUE);
    // 发送给我的控制设备所附加的下层对象
   // KdPrint(("Call next fs cdo (0x%08x).\n", MyCdoFilterDeviceExtension->AttachedToDeviceObject));
    Status = IoCallDriver(MyCdoFilterDeviceExtension->AttachedToDeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, FALSE);
    }

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        // 这里可以检查 Irp 中 vpb 值是否改变，有些可插拔设备是会改变的

        PDEVICE_OBJECT FsVolumeDevice = StorageDevice->Vpb->DeviceObject;

        // 由于设备的一些标志在前面没有初始化过，此时文件系统卷设备已经可以，可以根据它来初始化我们的过滤驱动标识了
        if (FsVolumeDevice->Flags & DO_BUFFERED_IO) {
            MyDevice->Flags |= DO_BUFFERED_IO;
        }

        if (FsVolumeDevice->Flags & DO_DIRECT_IO) {
            MyDevice->Flags |= DO_DIRECT_IO;
        }

        MyDevice->Flags &= ~DO_DEVICE_INITIALIZING;

        IoAttachDeviceToDeviceStackSafe(MyDevice, FsVolumeDevice, &DeviceExtension->AttachedToDeviceObject);

        //KdPrintWithFuncPrefix("Attached a fs volume deivce.\n");
    }
    else {
        IoDeleteDevice(MyDevice);
        // KdPrintWithFuncPrefix("Attach fs volume deivce failed");
        // KdPrint((" (0x%08x).\n", Irp->IoStatus.Status));
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

/*
 * 当文件系统的卷被挂载或解挂载时，这个函数会被调用。
 * 本驱动的控制设备和文件系统控制设备的过滤设备共用这些例程。
 * 暂不考虑控制设备发过来的请求，一般也不会有这样的请求产生。
 */
NTSTATUS
FsfFsControl(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    PFSF_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    //KdPrintThisFunction();

    // 如果是我的控制设备，则直接完成
    if (IsMyControlDeivce(DeviceObject)) {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        //   KdPrintWithFuncPrefix("Is my cdo.\n");
        return STATUS_SUCCESS;
    }

    // 主要处理文件系统控制设备的过滤设备
    switch (IoStackLocation->MinorFunction) {
    case IRP_MN_MOUNT_VOLUME:
        // 文件系统卷被挂载
        return FsfControlMountVolume(DeviceObject, Irp);
    case IRP_MN_LOAD_FILE_SYSTEM:
        //KdPrintWithFuncPrefix("Load file system.\n");
        break;
    case IRP_MN_USER_FS_REQUEST:
        // KdPrintWithFuncPrefix("User fs request.\n");
        if (IoStackLocation->Parameters.FileSystemControl.FsControlCode == FSCTL_DISMOUNT_VOLUME) {
            // 暂不处理文件系统卷被卸载的情况
        }
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}


NTSTATUS
FsfCleanupClose2(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    PFSF_DEVICE_EXTENSION DeviceExtension;
    DeviceExtension = DeviceObject->DeviceExtension;

    //KdPrintThisFunction();

    // 如果是我的控制设备，则直接完成
    if (IsMyControlDeivce(DeviceObject)) {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }
    // 如果是我的文件系统控制设备的过滤设备(控制设备过滤设备没有保存存储卷设备)，则直接下发
    if (DeviceExtension == NULL) {
        return FsfPassThrough(DeviceObject, Irp);
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}

NTSTATUS
FsfCleanupClose(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
)
{
    PFSF_DEVICE_EXTENSION DeviceExtension;
    DeviceExtension = DeviceObject->DeviceExtension;

    //KdPrintThisFunction();

   // 如果是我的控制设备，则直接完成  
    if (IsMyControlDeivce(DeviceObject)) {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }


    BOOLEAN Present = NULL;
    PBOOLEAN  DaclDefaulted = NULL;
    BOOLEAN  OwnerDefaulted = NULL;
    UNICODE_STRING Username = { 0 };
    PULONG  idsize = 16;
    PSID_NAME_USE SidType = SidTypeUser;
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    KEVENT WaitEvent;
    NTSTATUS Status;
    BOOLEAN SdAllocated = 0;
    SECURITY_SUBJECT_CONTEXT  SubjectSecurityContext = IoStackLocation->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext;
    PEPROCESS  PROCESS;
    POBJECT_NAME_INFORMATION NameInfo;
    ULONG ReturnLength = 0;
    SECURITY_SUBJECT_CONTEXT ssc;
    PACCESS_TOKEN at;
    NTSTATUS status;
    SECURITY_IMPERSONATION_LEVEL   tksl;
    PBOOLEAN  DaclPresent = 0;
    ULONG tempfile = 0;
    BOOLEAN                   SubjectContextLocked = 1;
    ACCESS_MASK               PreviouslyGrantedAccess = 0;
    PGENERIC_MAPPING          GenericMapping = 0;
    ACCESS_MASK              GrantedAccess = 0;
    NTSTATUS                 AccessStatus = 0;


    if (!init)
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
    }
    ULONG Mode = Irp->RequestorMode;
    CHAR* PROC = PsGetCurrentProcess();
    CHAR* NAME = PROC + 0x450;
    if (!strcmp(NAME, "mscorsvw.exe")
        || !strcmp(NAME, "svchost.exe")
        || !strcmp(NAME, "ngen.exe")
        || !strcmp(NAME, "MsMpEng.exe")
        || !strcmp(NAME, "sppsvc.exe")
        || !strcmp(NAME, "System")
        || !strcmp(NAME, "wermgr.exe")
        || !strcmp(NAME, "TiWorker.exe")
        || !strcmp(NAME, "sedsvc.exe")
        || !strcmp(NAME, "wuauclt.exe")
        || !strcmp(NAME, "explorer.exe")
        || !strcmp(NAME, "spoolsv.exe")
        )
   /*if (!strcmp(NAME, "explorer.exe")
       )*/
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
    }
    DWORD64 IntegrityLevel = 0;

    if (savecolse &&
        IoStackLocation->Parameters.SetFile.FileInformationClass == FileDispositionInformation) {
        PWSTR Buffer = ExAllocatePoolWithTag(1, 0x500, 8);
        GetPathByFileObject(IoStackLocation->FileObject, Buffer);
        DbgPrint("%S\n", Buffer);
        // 获取当前线程上下文
        SeCaptureSubjectContext(&ssc);
        //锁定当前上下文
        SeLockSubjectContext(&ssc);
        //获取token
        at = SeQuerySubjectContextToken(&ssc);
        //判断当前token类型。在这里我们对模拟令牌不感兴趣  
        ULONG ret2 = SeQueryInformationToken(at, TokenImpersonationLevel, &tksl);
        //获取token级别
        SeQueryInformationToken(at, TokenIntegrityLevel, &IntegrityLevel);
        //获取安全描述符
        PSECURITY_DESCRIPTOR     SecurityDescriptor = ExAllocatePoolWithTag(3, sizeof(SECURITY_DESCRIPTOR), 1);
        ObGetObjectSecurity(IoStackLocation->FileObject, &SecurityDescriptor, &DaclDefaulted);
        //检查安全描述符是否有效
        ULONG ret = 0;
        if (Mode == UserMode)
        {
            ret = RtlValidSecurityDescriptor(SecurityDescriptor);
        }
        else if (Mode == KernelMode)
        {
            ret = SeValidSecurityDescriptor(sizeof(SECURITY_DESCRIPTOR), SecurityDescriptor);
        }
        SeUnlockSubjectContext(&ssc);
        SeReleaseSubjectContext(&ssc);
        //如果是模拟令牌或者高权限以下或者没有安全描述符以及安全描述符无效我们则不感兴趣
        if (ret2 == STATUS_SUCCESS || IntegrityLevel < 0x3000 || SecurityDescriptor == 0 || !ret)
        {
            ExFreePoolWithTag(Buffer, 8);
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
        }
        //ssc2是全局上下文变量，也就是测试用例的上下文而不是高权限上下文
        SeLockSubjectContext(&ssc2);
        GENERIC_MAPPING* GenericMapping = (GENERIC_MAPPING*)IoGetFileObjectGenericMapping();
        PPRIVILEGE_SET Privileges = NULL;
        //判断是否有写入权限
        ULONG ret3 = SeAccessCheck(SecurityDescriptor, &ssc2, SubjectContextLocked, DELETE,
            0, 0, GenericMapping, UserMode, &GrantedAccess, &AccessStatus);
        if (ret3)
        {
            GetPathByFileObject(IoStackLocation->FileObject, Buffer);
            if (!wcscmp(Buffer, L"C:") || Buffer[0] == 0)
            {
            }
            //记录信息
            else
            {
                ULONG pid = PsGetProcessId(PROC);
                //pid数字转字符串
                CHAR idstr[6] = { 0 };
                for (int t = 5; t != -1; t--)
                {
                    idstr[t] = pid % 10 + '0';
                    pid = pid / 10;
                }
               
                CHAR buf[500] = { 0 };
                //wchar转char
                for (size_t i = 0; i < wcslen(Buffer); i++)
                {
                    if (Buffer[i] != 0)
                    {

                        buf[i] = Buffer[i];
                    }
                }
                IO_STATUS_BLOCK StatusBlock = { 0 };
                HANDLE filehand = 0;
                PDWORD64 read = NULL;
                if (save)
                {
                    save = 0;
                    StatusBlock = createFile(L"\\??\\C:\\BoomUsersCL.txt", GENERIC_ALL, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, 0, &filehand//保存句柄
                    );
                    save = 1;
                }
                INT ret = 0;
                while (ret != STATUS_END_OF_FILE)
                {
                    CHAR BUF[1024];
                    ret = ZwReadFile(filehand, NULL, NULL, NULL, &StatusBlock, BUF, 1024, NULL, NULL);
                }
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, " boomboomboom!!!\r\n", sizeof(" boomboomboom!!!\r\n"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   文件名 :", sizeof("   文件名 :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, buf, strnlen(buf, 500), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   进程名 :", sizeof("   进程名 :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, NAME, strnlen(NAME, 500), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n    进程id :", sizeof("\r\n    进程id :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, idstr, 6, NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n", sizeof("\r\n"), NULL, NULL);
                savecolse = 0;
                ZwClose(filehand);
                savecolse = 1;
            }
        }
        SeUnlockSubjectContext(&ssc2);
        ExFreePoolWithTag(Buffer, 8);
    }
    else if((save)&& 
    FileRenameInformation== IoStackLocation->Parameters.SetFile.FileInformationClass
    && Irp->AssociatedIrp.SystemBuffer)
    {
        PWSTR Buffer = ExAllocatePoolWithTag(1, 0x500, 8);
        PFILE_RENAME_INFORMATION fin = (PFILE_RENAME_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
        // 获取当前线程上下文
        SeCaptureSubjectContext(&ssc);
        //锁定当前上下文
        SeLockSubjectContext(&ssc);
        //获取token
        at = SeQuerySubjectContextToken(&ssc);
        //判断当前token类型。在这里我们对模拟令牌不感兴趣  
        ULONG ret2 = SeQueryInformationToken(at, TokenImpersonationLevel, &tksl);
        //获取token级别
        SeQueryInformationToken(at, TokenIntegrityLevel, &IntegrityLevel);
        //获取安全描述符
        PSECURITY_DESCRIPTOR     SecurityDescriptor = ExAllocatePoolWithTag(3, sizeof(SECURITY_DESCRIPTOR)*2, 1);
        ObGetObjectSecurity(IoStackLocation->Parameters.SetFile.FileObject, &SecurityDescriptor, &DaclDefaulted);
        //检查安全描述符是否有效
        ULONG ret = 0;
        if (Mode == UserMode)
        {
            ret = RtlValidSecurityDescriptor(SecurityDescriptor);
        }

        else if (Mode == KernelMode)
        {
            ret = SeValidSecurityDescriptor(sizeof(SECURITY_DESCRIPTOR), SecurityDescriptor);
        }
        SeUnlockSubjectContext(&ssc);
        SeReleaseSubjectContext(&ssc);
        //如果是模拟令牌或者高权限以下或者没有安全描述符以及安全描述符无效我们则不感兴趣
        if (ret2 == STATUS_SUCCESS || IntegrityLevel < 0x3000 || SecurityDescriptor == 0 || !ret)
        {
            ExFreePoolWithTag(Buffer, 8);
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
        }
        //ssc2是全局上下文变量，也就是测试用例的上下文而不是高权限上下文
        SeLockSubjectContext(&ssc2);
        GENERIC_MAPPING* GenericMapping = (GENERIC_MAPPING*)IoGetFileObjectGenericMapping();
        PPRIVILEGE_SET Privileges = NULL;
        //判断是否有写入权限
        ULONG ret3 = SeAccessCheck(SecurityDescriptor, &ssc2, SubjectContextLocked, DELETE,
            0, 0, GenericMapping, UserMode, &GrantedAccess, &AccessStatus);
        //有则记录
        if (ret3)
        {
            GetPathByFileObject(IoStackLocation->FileObject, Buffer);
            if (!wcscmp(Buffer, L"C:") || Buffer[0] == 0)
            {
            }
            //记录信息
            else
            {
                ULONG pid = PsGetProcessId(PROC);
                //pid数字转字符串
                CHAR idstr[6] = { 0 };
                for (int t = 5; t != -1; t--)
                {
                    idstr[t] = pid % 10 + '0';
                    pid = pid / 10;
                }

                CHAR buf[500] = { 0 };
                CHAR buf2[500] = { 0 };
                //wchar转char
                for (size_t i = 0; i < wcslen(Buffer); i++)
                {
                    if (Buffer[i] != 0)
                    {

                        buf[i] = Buffer[i];
                    }
                }
                for (size_t i = 0; i < wcslen(fin->FileName); i++)
                {
                    if (fin->FileName[i] != 0)
                    {

                        buf2[i] = fin->FileName[i];
                    }
                }
                IO_STATUS_BLOCK StatusBlock = { 0 };
                HANDLE filehand = 0;
                PDWORD64 read = NULL;
                if (save)
                {
                    save = 0;
                    StatusBlock = createFile(L"\\??\\C:\\BoomUsersMove.txt", GENERIC_ALL, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, 0, &filehand//保存句柄
                    );
                    save = 1;
                }
                INT ret = 0;
                while (ret != STATUS_END_OF_FILE)
                {
                    CHAR BUF[1024];
                    ret = ZwReadFile(filehand, NULL, NULL, NULL, &StatusBlock, BUF, 1024, NULL, NULL);
                }
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, " boomboomboom!!!\r\n", sizeof(" boomboomboom!!!\r\n"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   移动前文件名 :", sizeof("   移动前文件名 :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, buf, strnlen(buf, 500), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n    移动后文件名 :", sizeof("\r\n    移动后文件名 :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, buf2, strnlen(buf2, 500), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "   进程名 :", sizeof("   进程名 :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, NAME, strnlen(NAME, 500), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n    进程id :", sizeof("\r\n    进程id :"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, idstr, 6, NULL, NULL);
                if (!fin->RootDirectory)
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "    未设置根目录", sizeof("    未设置根目录"), NULL, NULL);
                else
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "    设置根目录", sizeof("    设置根目录"), NULL, NULL);
                if (IoStackLocation->Parameters.SetFile.ReplaceIfExists)
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "    可替换原文件", sizeof("    可替换原文件"), NULL, NULL);
                else
                    ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "    不可替换原文件", sizeof("    不可替换原文件"), NULL, NULL);
                ZwWriteFile(filehand, NULL, NULL, NULL, &StatusBlock, "\r\n", sizeof("\r\n"), NULL, NULL);
                savecolse = 0;
                ZwClose(filehand);
                savecolse = 1;
            }
        }
        SeUnlockSubjectContext(&ssc2);
        ExFreePoolWithTag(Buffer, 8);
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}

 
    

BOOLEAN
FsfFastIoCheckIfPossible(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in BOOLEAN CheckForReadOperation,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoRead(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoWrite(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoQueryBasicInfo(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __out PFILE_BASIC_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoQueryStandardInfo(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __out PFILE_STANDARD_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoLock(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoUnlockSingle(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoUnlockAll(
    __in struct _FILE_OBJECT* FileObject,
    __in PEPROCESS ProcessId,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoUnlockAllByKey(
    __in struct _FILE_OBJECT* FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoDeviceControl(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __in_opt PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_opt PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

VOID
FsfFastIoDetachDevice(
    __in struct _DEVICE_OBJECT* SourceDevice,
    __in struct _DEVICE_OBJECT* TargetDevice
)
{
}

BOOLEAN
FsfFastIoQueryNetworkOpenInfo(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __out struct _FILE_NETWORK_OPEN_INFORMATION* Buffer,
    __out struct _IO_STATUS_BLOCK* IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoMdlRead(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoMdlReadComplete(
    __in struct _FILE_OBJECT* FileObject,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoPrepareMdlWrite(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoWriteComplete(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoReadCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PVOID Buffer,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __out struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoWriteCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __in PVOID Buffer,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoReadCompleteCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoWriteCompleteCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

BOOLEAN
FsfFastIoQueryOpen(
    __inout struct _IRP* Irp,
    __out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in struct _DEVICE_OBJECT* DeviceObject
)
{
    return FALSE;
}

/*
 * 文件系统激活和注销时的回调
 * DeviceObject: 为文件系统控制设备，但为了提高效率，也有可能是文件系统识别器设备（该设备一般由 Fs_Rec 生成）；
 * FsActive:     是激活还是注销
 */
VOID
FsfFsNotification(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __in BOOLEAN FsActive
)
{
    UNICODE_STRING DriverName;
    POBJECT_NAME_INFORMATION NameInfo;
    ULONG ReturnLength = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT NewDeviceObject;
    PFSF_DEVICE_EXTENSION DeviceExtension;
    char Buff[512];

    // KdPrintThisFunction();

     // 检查是不是想要处理文件系统设备类型
    if (DeviceObject->DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM /*&&
        DeviceObject->DeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM*/) {
        return;
    }

    if (FsActive) {
        // 如果是激活

      //  KdPrintWithFuncPrefix("Active.\n");

        // 检查该设备是否为微软的文件系统识别器设备（是否是 \FileSystem\Fs_Rec 驱动生成的设备, 这种方法现在可行，但不能保证一直有效）
        RtlInitUnicodeString(&DriverName, L"\\FileSystem\\Fs_Rec");
        NameInfo = (POBJECT_NAME_INFORMATION)Buff;
        ObQueryNameString(DeviceObject->DriverObject, NameInfo, sizeof(Buff), &ReturnLength);
        if (RtlCompareUnicodeString(&NameInfo->Name, &DriverName, TRUE) == 0) {
            // KdPrintWithFuncPrefix("A file system recognizer here!.\n");
            return;
        }



        // 创建过滤设备, 匿名，类型和属性与文件系统设备相同
        Status = IoCreateDevice(g_MyDriver,
            sizeof(FSF_DEVICE_EXTENSION),
            NULL,
            DeviceObject->DeviceType,
            0,
            FALSE,
            &NewDeviceObject);
        if (!NT_SUCCESS(Status)) {
            return;
        }

        // 设置新设备的属性
        if (DeviceObject->Flags & DO_BUFFERED_IO) {
            NewDeviceObject->Flags |= DO_BUFFERED_IO;
        }

        if (DeviceObject->Flags & DO_DIRECT_IO) {
            NewDeviceObject->Flags |= DO_DIRECT_IO;
        }

        if (DeviceObject->Characteristics & FILE_DEVICE_SECURE_OPEN) {
            NewDeviceObject->Characteristics |= FILE_DEVICE_SECURE_OPEN;
        }

        DeviceExtension = NewDeviceObject->DeviceExtension;
        IoAttachDeviceToDeviceStackSafe(NewDeviceObject, DeviceObject, &DeviceExtension->AttachedToDeviceObject);
        // 在扩展中打上标志，以识别为该驱动的文件系统控制设备过滤驱动
        DeviceExtension->TypeFlag = FSF_DEVICE_FLAG;

        // 记录控制设备的名字
        RtlInitEmptyUnicodeString(&DeviceExtension->AttachedToDeviceName, DeviceExtension->AttachedToDeviceNameBuff, sizeof(DeviceExtension->AttachedToDeviceNameBuff));
        ObQueryNameString(DeviceObject, NameInfo, sizeof(Buff), &ReturnLength);
        RtlCopyUnicodeString(&DeviceExtension->AttachedToDeviceName, &NameInfo->Name);

        // KdPrintWithFuncPrefix("Create and attach the fs control device ");
        // KdPrint(("(0x%08x).\n", DeviceObject));

        NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;


        // 前面绑定文件系统控制设备只是为了去监听那些还未被挂载进系统的卷，对于已挂载的文件系统卷需要手动枚举
        // 文件系统驱动生成两种设备，一种为文件系统控制设备(一般来说只生成一个 CDO)，即此函数传入的设备对象参数，另一种为文件系统卷设备，即我们最终需要挂接并过滤的
        // 文件系统卷设备有可能有多个，文件系统驱动会为每一个该文件系统类型的磁盘卷生成一个文件系统卷设备
        {
            ULONG DeviceCount = 0;
            PDEVICE_OBJECT* DeviceList;
            PDEVICE_OBJECT StorageDevice;
            PDEVICE_OBJECT MyDevice;
            PFSF_DEVICE_EXTENSION DeviceExtension;
            ULONG i = 0;

            IoEnumerateDeviceObjectList(DeviceObject->DriverObject, NULL, 0, &DeviceCount);
            DeviceList = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, DeviceCount * sizeof(PDEVICE_OBJECT));
            IoEnumerateDeviceObjectList(DeviceObject->DriverObject, DeviceList, DeviceCount * sizeof(PDEVICE_OBJECT), &DeviceCount);
            for (; i < DeviceCount; i++) {
                PDEVICE_OBJECT DeviceObjectEntry = DeviceList[i];

                // 如果该设备对象是文件系统驱动的控制对象，则略过， 如果是其它设备类型的也略过，如 U 盘类型呀，因为上面我们只关注 Disk 类型
                // 暂不考虑已经被我们挂接过的设备
                if (DeviceObjectEntry == DeviceObject || DeviceObjectEntry->DeviceType != DeviceObject->DeviceType) {
                    continue;
                }

                // 得到卷设备驱动
                IoGetDiskDeviceObject(DeviceObjectEntry, &StorageDevice);
                Status = IoCreateDevice(g_MyDriver,
                    sizeof(FSF_DEVICE_EXTENSION),
                    NULL,
                    DeviceObject->DeviceType,
                    0,
                    FALSE,
                    &MyDevice);

                DeviceExtension = MyDevice->DeviceExtension;
                DeviceExtension->StorageDevice = StorageDevice;
                DeviceExtension->TypeFlag = FSF_DEVICE_FLAG;

                // 记录下存储设备的名字
                RtlInitEmptyUnicodeString(&DeviceExtension->AttachedToDeviceName,
                    DeviceExtension->AttachedToDeviceNameBuff,
                    sizeof(DeviceExtension->AttachedToDeviceNameBuff));
                NameInfo = (POBJECT_NAME_INFORMATION)Buff;
                ObQueryNameString(StorageDevice,
                    NameInfo,
                    sizeof(Buff),
                    &ReturnLength);
                RtlCopyUnicodeString(&DeviceExtension->AttachedToDeviceName, &NameInfo->Name);

                // 由于设备的一些标志在前面没有初始化过，此时文件系统卷设备已经可以，可以根据它来初始化我们的过滤驱动标识了
                if (DeviceObjectEntry->Flags & DO_BUFFERED_IO) {
                    MyDevice->Flags |= DO_BUFFERED_IO;
                }

                if (DeviceObjectEntry->Flags & DO_DIRECT_IO) {
                    MyDevice->Flags |= DO_DIRECT_IO;
                }

                MyDevice->Flags &= ~DO_DEVICE_INITIALIZING;

                IoAttachDeviceToDeviceStackSafe(MyDevice, DeviceObjectEntry, &DeviceExtension->AttachedToDeviceObject);
                //KdPrintWithFuncPrefix("Create and attach a fs volume device ");
              //  KdPrint(("(0x%08x).\n", MyDevice));
            }
        }
    }
    else {
        // 如果是注销

        // 遍历该设备上的所有附加设备，如果是我的设备，则去掉附加并删除
        PDEVICE_OBJECT MyDeivce = DeviceObject->AttachedDevice;

        //    KdPrintWithFuncPrefix("Inactive.\n");

        while (MyDeivce != NULL) {
            PDEVICE_OBJECT TempDevice = MyDeivce->AttachedDevice;

            if (IsMyControlDeivce(MyDeivce)) {
                IoDetachDevice(MyDeivce);
                IoDeleteDevice(MyDeivce);
                return;
            }

            MyDeivce = TempDevice;
        }
    }
}




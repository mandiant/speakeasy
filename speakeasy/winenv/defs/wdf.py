# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct

import speakeasy.winenv.defs.usb as usbdefs
from speakeasy.struct import EmuStruct, Ptr, EmuUnion, Enum


WdfUsbTargetDeviceSelectConfigType = Enum()
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeInvalid = 0
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeDeconfig = 1
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeSingleInterface = 2
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeMultiInterface = 3
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeInterfacesPairs = 4
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeInterfacesDescriptor = 5
WdfUsbTargetDeviceSelectConfigType.WdfUsbTargetDeviceSelectConfigTypeUrb = 6

WdfUsbTargetDeviceSelectSettingType = Enum()
WdfUsbTargetDeviceSelectSettingType.WdfUsbInterfaceSelectSettingTypeDescriptor = 0x10
WdfUsbTargetDeviceSelectSettingType.WdfUsbInterfaceSelectSettingTypeSetting = 0x11
WdfUsbTargetDeviceSelectSettingType.WdfUsbInterfaceSelectSettingTypeUrb = 0x12

WDF_USB_PIPE_TYPE = Enum()
WDF_USB_PIPE_TYPE.WdfUsbPipeTypeInvalid = 0
WDF_USB_PIPE_TYPE.WdfUsbPipeTypeControl = 1
WDF_USB_PIPE_TYPE.WdfUsbPipeTypeIsochronous = 2
WDF_USB_PIPE_TYPE.WdfUsbPipeTypeBulk = 3
WDF_USB_PIPE_TYPE.WdfUsbPipeTypeInterrupt = 4

WDF_USB_DEVICE_TRAIT_SELF_POWERED = 1
WDF_USB_DEVICE_TRAIT_REMOTE_WAKE_CAPABLE = 2
WDF_USB_DEVICE_TRAIT_AT_HIGH_SPEED = 4


class WDF_VERSION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Major = ct.c_uint32
        self.Minor = ct.c_uint32
        self.Build = ct.c_uint32


class WDF_BIND_INFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.Component = Ptr
        self.Version = WDF_VERSION
        self.FuncCount = ct.c_uint32
        self.FuncTable = Ptr
        self.Module = Ptr


class WDF_USB_DEVICE_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.UsbdVersionInformation = usbdefs.USBD_VERSION_INFORMATION
        self.HcdPortCapabilities = ct.c_uint32
        self.Traits = ct.c_uint32


class WDF_DRIVER_CONFIG(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.EvtDriverDeviceAdd = Ptr
        self.EvtDriverUnload = Ptr
        self.DriverInitFlags = ct.c_uint32
        self.DriverPoolTag = ct.c_uint32


class WDF_COMPONENT_GLOBALS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data = ct.c_uint8 * 0x100


class WDF_TYPED_CONTEXT_WORKER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data = ct.c_uint8 * 0x100


class WDF_USB_PIPE_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.MaximumPacketSize = ct.c_uint32
        self.EndpointAddress = ct.c_uint8
        self.Interval = ct.c_uint8
        self.SettingIndex = ct.c_uint8
        self.PipeType = ct.c_uint32
        self.MaximumTransferSize = ct.c_uint32


class WDF_PNPPOWER_EVENT_CALLBACKS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.EvtDeviceD0Entry = Ptr
        self.EvtDeviceD0EntryPostInterruptsEnabled = Ptr
        self.EvtDeviceD0Exit = Ptr
        self.EvtDeviceD0ExitPreInterruptsDisabled = Ptr
        self.EvtDevicePrepareHardware = Ptr
        self.EvtDeviceReleaseHardware = Ptr
        self.EvtDeviceSelfManagedIoCleanup = Ptr
        self.EvtDeviceSelfManagedIoFlush = Ptr
        self.EvtDeviceSelfManagedIoInit = Ptr
        self.EvtDeviceSelfManagedIoSuspend = Ptr
        self.EvtDeviceSelfManagedIoRestart = Ptr
        self.EvtDeviceSurpriseRemoval = Ptr
        self.EvtDeviceQueryRemove = Ptr
        self.EvtDeviceQueryStop = Ptr
        self.EvtDeviceUsageNotification = Ptr
        self.EvtDeviceRelationsQuery = Ptr
        self.EvtDeviceUsageNotificationEx = Ptr


class _InterfaceDescriptor(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.InterfaceDescriptor = Ptr


class Interface(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.SettingIndex = ct.c_uint8


class InterfaceUrb(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Urb = Ptr


class InterfaceTypes(EmuUnion):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Descriptor = _InterfaceDescriptor(ptr_size).get_cstruct()
        self.Interface = Interface(ptr_size).get_cstruct()
        self.Urb = InterfaceUrb(ptr_size).get_cstruct()


class WDF_USB_INTERFACE_SELECT_SETTING_PARAMS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.Type = ct.c_uint32
        self.Types = InterfaceTypes


class Descriptor(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ConfigurationDescriptor = Ptr
        self.InterfaceDescriptors = Ptr
        self.NumInterfaceDescriptors = ct.c_uint32


class Urb(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Urb = Ptr


class SingleInterface(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.NumberConfiguredPipes = ct.c_uint8
        self.ConfiguredUsbInterface = Ptr


class MultiInterface(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.NumberInterfaces = ct.c_uint8
        self.Pairs = Ptr
        self.NumberOfConfiguredInterfaces = ct.c_uint8


class Types(EmuUnion):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Descriptor = Descriptor(ptr_size).get_cstruct()
        self.Urb = Urb(ptr_size).get_cstruct()
        self.SingleInterface = SingleInterface(ptr_size).get_cstruct()
        self.MultiInterface = MultiInterface(ptr_size).get_cstruct()


class WDF_USB_DEVICE_SELECT_CONFIG_PARAMS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.Type = ct.c_uint32
        self.Types = Types


class WDF_IO_QUEUE_CONFIG(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.DispatchType = Ptr
        self.PowerManaged = Ptr
        self.AllowZeroLengthRequests = ct.c_uint8
        self.DefaultQueue = ct.c_uint8
        self.EvtIoDefault = Ptr
        self.EvtIoRead = Ptr
        self.EvtIoWrite = Ptr
        self.EvtIoDeviceControl = Ptr
        self.EvtIoInternalDeviceControl = Ptr
        self.EvtIoStop = Ptr
        self.EvtIoResume = Ptr
        self.EvtIoCanceledOnQueue = Ptr
        self.NumberOfPresentedRequests = ct.c_uint32
        self.Driver = Ptr


class WDFFUNCTIONS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.pfnWdfChildListCreate = Ptr
        self.pfnWdfChildListGetDevice = Ptr
        self.pfnWdfChildListRetrievePdo = Ptr
        self.pfnWdfChildListRetrieveAddressDescription = Ptr
        self.pfnWdfChildListBeginScan = Ptr
        self.pfnWdfChildListEndScan = Ptr
        self.pfnWdfChildListBeginIteration = Ptr
        self.pfnWdfChildListRetrieveNextDevice = Ptr
        self.pfnWdfChildListEndIteration = Ptr
        self.pfnWdfChildListAddOrUpdateChildDescriptionAsPresent = Ptr
        self.pfnWdfChildListUpdateChildDescriptionAsMissing = Ptr
        self.pfnWdfChildListUpdateAllChildDescriptionsAsPresent = Ptr
        self.pfnWdfChildListRequestChildEject = Ptr
        self.pfnWdfCollectionCreate = Ptr
        self.pfnWdfCollectionGetCount = Ptr
        self.pfnWdfCollectionAdd = Ptr
        self.pfnWdfCollectionRemove = Ptr
        self.pfnWdfCollectionRemoveItem = Ptr
        self.pfnWdfCollectionGetItem = Ptr
        self.pfnWdfCollectionGetFirstItem = Ptr
        self.pfnWdfCollectionGetLastItem = Ptr
        self.pfnWdfCommonBufferCreate = Ptr
        self.pfnWdfCommonBufferGetAlignedVirtualAddress = Ptr
        self.pfnWdfCommonBufferGetAlignedLogicalAddress = Ptr
        self.pfnWdfCommonBufferGetLength = Ptr
        self.pfnWdfControlDeviceInitAllocate = Ptr
        self.pfnWdfControlDeviceInitSetShutdownNotification = Ptr
        self.pfnWdfControlFinishInitializing = Ptr
        self.pfnWdfDeviceGetDeviceState = Ptr
        self.pfnWdfDeviceSetDeviceState = Ptr
        self.pfnWdfWdmDeviceGetWdfDeviceHandle = Ptr
        self.pfnWdfDeviceWdmGetDeviceObject = Ptr
        self.pfnWdfDeviceWdmGetAttachedDevice = Ptr
        self.pfnWdfDeviceWdmGetPhysicalDevice = Ptr
        self.pfnWdfDeviceWdmDispatchPreprocessedIrp = Ptr
        self.pfnWdfDeviceAddDependentUsageDeviceObject = Ptr
        self.pfnWdfDeviceAddRemovalRelationsPhysicalDevice = Ptr
        self.pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice = Ptr
        self.pfnWdfDeviceClearRemovalRelationsDevices = Ptr
        self.pfnWdfDeviceGetDriver = Ptr
        self.pfnWdfDeviceRetrieveDeviceName = Ptr
        self.pfnWdfDeviceAssignMofResourceName = Ptr
        self.pfnWdfDeviceGetIoTarget = Ptr
        self.pfnWdfDeviceGetDevicePnpState = Ptr
        self.pfnWdfDeviceGetDevicePowerState = Ptr
        self.pfnWdfDeviceGetDevicePowerPolicyState = Ptr
        self.pfnWdfDeviceAssignS0IdleSettings = Ptr
        self.pfnWdfDeviceAssignSxWakeSettings = Ptr
        self.pfnWdfDeviceOpenRegistryKey = Ptr
        self.pfnWdfDeviceSetSpecialFileSupport = Ptr
        self.pfnWdfDeviceSetCharacteristics = Ptr
        self.pfnWdfDeviceGetCharacteristics = Ptr
        self.pfnWdfDeviceGetAlignmentRequirement = Ptr
        self.pfnWdfDeviceSetAlignmentRequirement = Ptr
        self.pfnWdfDeviceInitFree = Ptr
        self.pfnWdfDeviceInitSetPnpPowerEventCallbacks = Ptr
        self.pfnWdfDeviceInitSetPowerPolicyEventCallbacks = Ptr
        self.pfnWdfDeviceInitSetPowerPolicyOwnership = Ptr
        self.pfnWdfDeviceInitRegisterPnpStateChangeCallback = Ptr
        self.pfnWdfDeviceInitRegisterPowerStateChangeCallback = Ptr
        self.pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback = Ptr
        self.pfnWdfDeviceInitSetIoType = Ptr
        self.pfnWdfDeviceInitSetExclusive = Ptr
        self.pfnWdfDeviceInitSetPowerNotPageable = Ptr
        self.pfnWdfDeviceInitSetPowerPageable = Ptr
        self.pfnWdfDeviceInitSetPowerInrush = Ptr
        self.pfnWdfDeviceInitSetDeviceType = Ptr
        self.pfnWdfDeviceInitAssignName = Ptr
        self.pfnWdfDeviceInitAssignSDDLString = Ptr
        self.pfnWdfDeviceInitSetDeviceClass = Ptr
        self.pfnWdfDeviceInitSetCharacteristics = Ptr
        self.pfnWdfDeviceInitSetFileObjectConfig = Ptr
        self.pfnWdfDeviceInitSetRequestAttributes = Ptr
        self.pfnWdfDeviceInitAssignWdmIrpPreprocessCallback = Ptr
        self.pfnWdfDeviceInitSetIoInCallerContextCallback = Ptr
        self.pfnWdfDeviceCreate = Ptr
        self.pfnWdfDeviceSetStaticStopRemove = Ptr
        self.pfnWdfDeviceCreateDeviceInterface = Ptr
        self.pfnWdfDeviceSetDeviceInterfaceState = Ptr
        self.pfnWdfDeviceRetrieveDeviceInterfaceString = Ptr
        self.pfnWdfDeviceCreateSymbolicLink = Ptr
        self.pfnWdfDeviceQueryProperty = Ptr
        self.pfnWdfDeviceAllocAndQueryProperty = Ptr
        self.pfnWdfDeviceSetPnpCapabilities = Ptr
        self.pfnWdfDeviceSetPowerCapabilities = Ptr
        self.pfnWdfDeviceSetBusInformationForChildren = Ptr
        self.pfnWdfDeviceIndicateWakeStatus = Ptr
        self.pfnWdfDeviceSetFailed = Ptr
        self.pfnWdfDeviceStopIdleNoTrack = Ptr
        self.pfnWdfDeviceResumeIdleNoTrack = Ptr
        self.pfnWdfDeviceGetFileObject = Ptr
        self.pfnWdfDeviceEnqueueRequest = Ptr
        self.pfnWdfDeviceGetDefaultQueue = Ptr
        self.pfnWdfDeviceConfigureRequestDispatching = Ptr
        self.pfnWdfDmaEnablerCreate = Ptr
        self.pfnWdfDmaEnablerGetMaximumLength = Ptr
        self.pfnWdfDmaEnablerGetMaximumScatterGatherElements = Ptr
        self.pfnWdfDmaEnablerSetMaximumScatterGatherElements = Ptr
        self.pfnWdfDmaTransactionCreate = Ptr
        self.pfnWdfDmaTransactionInitialize = Ptr
        self.pfnWdfDmaTransactionInitializeUsingRequest = Ptr
        self.pfnWdfDmaTransactionExecute = Ptr
        self.pfnWdfDmaTransactionRelease = Ptr
        self.pfnWdfDmaTransactionDmaCompleted = Ptr
        self.pfnWdfDmaTransactionDmaCompletedWithLength = Ptr
        self.pfnWdfDmaTransactionDmaCompletedFinal = Ptr
        self.pfnWdfDmaTransactionGetBytesTransferred = Ptr
        self.pfnWdfDmaTransactionSetMaximumLength = Ptr
        self.pfnWdfDmaTransactionGetRequest = Ptr
        self.pfnWdfDmaTransactionGetCurrentDmaTransferLength = Ptr
        self.pfnWdfDmaTransactionGetDevice = Ptr
        self.pfnWdfDpcCreate = Ptr
        self.pfnWdfDpcEnqueue = Ptr
        self.pfnWdfDpcCancel = Ptr
        self.pfnWdfDpcGetParentObject = Ptr
        self.pfnWdfDpcWdmGetDpc = Ptr
        self.pfnWdfDriverCreate = Ptr
        self.pfnWdfDriverGetRegistryPath = Ptr
        self.pfnWdfDriverWdmGetDriverObject = Ptr
        self.pfnWdfDriverOpenParametersRegistryKey = Ptr
        self.pfnWdfWdmDriverGetWdfDriverHandle = Ptr
        self.pfnWdfDriverRegisterTraceInfo = Ptr
        self.pfnWdfDriverRetrieveVersionString = Ptr
        self.pfnWdfDriverIsVersionAvailable = Ptr
        self.pfnWdfFdoInitWdmGetPhysicalDevice = Ptr
        self.pfnWdfFdoInitOpenRegistryKey = Ptr
        self.pfnWdfFdoInitQueryProperty = Ptr
        self.pfnWdfFdoInitAllocAndQueryProperty = Ptr
        self.pfnWdfFdoInitSetEventCallbacks = Ptr
        self.pfnWdfFdoInitSetFilter = Ptr
        self.pfnWdfFdoInitSetDefaultChildListConfig = Ptr
        self.pfnWdfFdoQueryForInterface = Ptr
        self.pfnWdfFdoGetDefaultChildList = Ptr
        self.pfnWdfFdoAddStaticChild = Ptr
        self.pfnWdfFdoLockStaticChildListForIteration = Ptr
        self.pfnWdfFdoRetrieveNextStaticChild = Ptr
        self.pfnWdfFdoUnlockStaticChildListFromIteration = Ptr
        self.pfnWdfFileObjectGetFileName = Ptr
        self.pfnWdfFileObjectGetFlags = Ptr
        self.pfnWdfFileObjectGetDevice = Ptr
        self.pfnWdfFileObjectWdmGetFileObject = Ptr
        self.pfnWdfInterruptCreate = Ptr
        self.pfnWdfInterruptQueueDpcForIsr = Ptr
        self.pfnWdfInterruptSynchronize = Ptr
        self.pfnWdfInterruptAcquireLock = Ptr
        self.pfnWdfInterruptReleaseLock = Ptr
        self.pfnWdfInterruptEnable = Ptr
        self.pfnWdfInterruptDisable = Ptr
        self.pfnWdfInterruptWdmGetInterrupt = Ptr
        self.pfnWdfInterruptGetInfo = Ptr
        self.pfnWdfInterruptSetPolicy = Ptr
        self.pfnWdfInterruptGetDevice = Ptr
        self.pfnWdfIoQueueCreate = Ptr
        self.pfnWdfIoQueueGetState = Ptr
        self.pfnWdfIoQueueStart = Ptr
        self.pfnWdfIoQueueStop = Ptr
        self.pfnWdfIoQueueStopSynchronously = Ptr
        self.pfnWdfIoQueueGetDevice = Ptr
        self.pfnWdfIoQueueRetrieveNextRequest = Ptr
        self.pfnWdfIoQueueRetrieveRequestByFileObject = Ptr
        self.pfnWdfIoQueueFindRequest = Ptr
        self.pfnWdfIoQueueRetrieveFoundRequest = Ptr
        self.pfnWdfIoQueueDrainSynchronously = Ptr
        self.pfnWdfIoQueueDrain = Ptr
        self.pfnWdfIoQueuePurgeSynchronously = Ptr
        self.pfnWdfIoQueuePurge = Ptr
        self.pfnWdfIoQueueReadyNotify = Ptr
        self.pfnWdfIoTargetCreate = Ptr
        self.pfnWdfIoTargetOpen = Ptr
        self.pfnWdfIoTargetCloseForQueryRemove = Ptr
        self.pfnWdfIoTargetClose = Ptr
        self.pfnWdfIoTargetStart = Ptr
        self.pfnWdfIoTargetStop = Ptr
        self.pfnWdfIoTargetGetState = Ptr
        self.pfnWdfIoTargetGetDevice = Ptr
        self.pfnWdfIoTargetQueryTargetProperty = Ptr
        self.pfnWdfIoTargetAllocAndQueryTargetProperty = Ptr
        self.pfnWdfIoTargetQueryForInterface = Ptr
        self.pfnWdfIoTargetWdmGetTargetDeviceObject = Ptr
        self.pfnWdfIoTargetWdmGetTargetPhysicalDevice = Ptr
        self.pfnWdfIoTargetWdmGetTargetFileObject = Ptr
        self.pfnWdfIoTargetWdmGetTargetFileHandle = Ptr
        self.pfnWdfIoTargetSendReadSynchronously = Ptr
        self.pfnWdfIoTargetFormatRequestForRead = Ptr
        self.pfnWdfIoTargetSendWriteSynchronously = Ptr
        self.pfnWdfIoTargetFormatRequestForWrite = Ptr
        self.pfnWdfIoTargetSendIoctlSynchronously = Ptr
        self.pfnWdfIoTargetFormatRequestForIoctl = Ptr
        self.pfnWdfIoTargetSendInternalIoctlSynchronously = Ptr
        self.pfnWdfIoTargetFormatRequestForInternalIoctl = Ptr
        self.pfnWdfIoTargetSendInternalIoctlOthersSynchronously = Ptr
        self.pfnWdfIoTargetFormatRequestForInternalIoctlOthers = Ptr
        self.pfnWdfMemoryCreate = Ptr
        self.pfnWdfMemoryCreatePreallocated = Ptr
        self.pfnWdfMemoryGetBuffer = Ptr
        self.pfnWdfMemoryAssignBuffer = Ptr
        self.pfnWdfMemoryCopyToBuffer = Ptr
        self.pfnWdfMemoryCopyFromBuffer = Ptr
        self.pfnWdfLookasideListCreate = Ptr
        self.pfnWdfMemoryCreateFromLookaside = Ptr
        self.pfnWdfDeviceMiniportCreate = Ptr
        self.pfnWdfDriverMiniportUnload = Ptr
        self.pfnWdfObjectGetTypedContextWorker = Ptr
        self.pfnWdfObjectAllocateContext = Ptr
        self.pfnWdfObjectContextGetObject = Ptr
        self.pfnWdfObjectReferenceActual = Ptr
        self.pfnWdfObjectDereferenceActual = Ptr
        self.pfnWdfObjectCreate = Ptr
        self.pfnWdfObjectDelete = Ptr
        self.pfnWdfObjectQuery = Ptr
        self.pfnWdfPdoInitAllocate = Ptr
        self.pfnWdfPdoInitSetEventCallbacks = Ptr
        self.pfnWdfPdoInitAssignDeviceID = Ptr
        self.pfnWdfPdoInitAssignInstanceID = Ptr
        self.pfnWdfPdoInitAddHardwareID = Ptr
        self.pfnWdfPdoInitAddCompatibleID = Ptr
        self.pfnWdfPdoInitAddDeviceText = Ptr
        self.pfnWdfPdoInitSetDefaultLocale = Ptr
        self.pfnWdfPdoInitAssignRawDevice = Ptr
        self.pfnWdfPdoMarkMissing = Ptr
        self.pfnWdfPdoRequestEject = Ptr
        self.pfnWdfPdoGetParent = Ptr
        self.pfnWdfPdoRetrieveIdentificationDescription = Ptr
        self.pfnWdfPdoRetrieveAddressDescription = Ptr
        self.pfnWdfPdoUpdateAddressDescription = Ptr
        self.pfnWdfPdoAddEjectionRelationsPhysicalDevice = Ptr
        self.pfnWdfPdoRemoveEjectionRelationsPhysicalDevice = Ptr
        self.pfnWdfPdoClearEjectionRelationsDevices = Ptr
        self.pfnWdfDeviceAddQueryInterface = Ptr
        self.pfnWdfRegistryOpenKey = Ptr
        self.pfnWdfRegistryCreateKey = Ptr
        self.pfnWdfRegistryClose = Ptr
        self.pfnWdfRegistryWdmGetHandle = Ptr
        self.pfnWdfRegistryRemoveKey = Ptr
        self.pfnWdfRegistryRemoveValue = Ptr
        self.pfnWdfRegistryQueryValue = Ptr
        self.pfnWdfRegistryQueryMemory = Ptr
        self.pfnWdfRegistryQueryMultiString = Ptr
        self.pfnWdfRegistryQueryUnicodeString = Ptr
        self.pfnWdfRegistryQueryString = Ptr
        self.pfnWdfRegistryQueryULong = Ptr
        self.pfnWdfRegistryAssignValue = Ptr
        self.pfnWdfRegistryAssignMemory = Ptr
        self.pfnWdfRegistryAssignMultiString = Ptr
        self.pfnWdfRegistryAssignUnicodeString = Ptr
        self.pfnWdfRegistryAssignString = Ptr
        self.pfnWdfRegistryAssignULong = Ptr
        self.pfnWdfRequestCreate = Ptr
        self.pfnWdfRequestCreateFromIrp = Ptr
        self.pfnWdfRequestReuse = Ptr
        self.pfnWdfRequestChangeTarget = Ptr
        self.pfnWdfRequestFormatRequestUsingCurrentType = Ptr
        self.pfnWdfRequestWdmFormatUsingStackLocation = Ptr
        self.pfnWdfRequestSend = Ptr
        self.pfnWdfRequestGetStatus = Ptr
        self.pfnWdfRequestMarkCancelable = Ptr
        self.pfnWdfRequestUnmarkCancelable = Ptr
        self.pfnWdfRequestIsCanceled = Ptr
        self.pfnWdfRequestCancelSentRequest = Ptr
        self.pfnWdfRequestIsFrom32BitProcess = Ptr
        self.pfnWdfRequestSetCompletionRoutine = Ptr
        self.pfnWdfRequestGetCompletionParams = Ptr
        self.pfnWdfRequestAllocateTimer = Ptr
        self.pfnWdfRequestComplete = Ptr
        self.pfnWdfRequestCompleteWithPriorityBoost = Ptr
        self.pfnWdfRequestCompleteWithInformation = Ptr
        self.pfnWdfRequestGetParameters = Ptr
        self.pfnWdfRequestRetrieveInputMemory = Ptr
        self.pfnWdfRequestRetrieveOutputMemory = Ptr
        self.pfnWdfRequestRetrieveInputBuffer = Ptr
        self.pfnWdfRequestRetrieveOutputBuffer = Ptr
        self.pfnWdfRequestRetrieveInputWdmMdl = Ptr
        self.pfnWdfRequestRetrieveOutputWdmMdl = Ptr
        self.pfnWdfRequestRetrieveUnsafeUserInputBuffer = Ptr
        self.pfnWdfRequestRetrieveUnsafeUserOutputBuffer = Ptr
        self.pfnWdfRequestSetInformation = Ptr
        self.pfnWdfRequestGetInformation = Ptr
        self.pfnWdfRequestGetFileObject = Ptr
        self.pfnWdfRequestProbeAndLockUserBufferForRead = Ptr
        self.pfnWdfRequestProbeAndLockUserBufferForWrite = Ptr
        self.pfnWdfRequestGetRequestorMode = Ptr
        self.pfnWdfRequestForwardToIoQueue = Ptr
        self.pfnWdfRequestGetIoQueue = Ptr
        self.pfnWdfRequestRequeue = Ptr
        self.pfnWdfRequestStopAcknowledge = Ptr
        self.pfnWdfRequestWdmGetIrp = Ptr
        self.pfnWdfIoResourceRequirementsListSetSlotNumber = Ptr
        self.pfnWdfIoResourceRequirementsListSetInterfaceType = Ptr
        self.pfnWdfIoResourceRequirementsListAppendIoResList = Ptr
        self.pfnWdfIoResourceRequirementsListInsertIoResList = Ptr
        self.pfnWdfIoResourceRequirementsListGetCount = Ptr
        self.pfnWdfIoResourceRequirementsListGetIoResList = Ptr
        self.pfnWdfIoResourceRequirementsListRemove = Ptr
        self.pfnWdfIoResourceRequirementsListRemoveByIoResList = Ptr
        self.pfnWdfIoResourceListCreate = Ptr
        self.pfnWdfIoResourceListAppendDescriptor = Ptr
        self.pfnWdfIoResourceListInsertDescriptor = Ptr
        self.pfnWdfIoResourceListUpdateDescriptor = Ptr
        self.pfnWdfIoResourceListGetCount = Ptr
        self.pfnWdfIoResourceListGetDescriptor = Ptr
        self.pfnWdfIoResourceListRemove = Ptr
        self.pfnWdfIoResourceListRemoveByDescriptor = Ptr
        self.pfnWdfCmResourceListAppendDescriptor = Ptr
        self.pfnWdfCmResourceListInsertDescriptor = Ptr
        self.pfnWdfCmResourceListGetCount = Ptr
        self.pfnWdfCmResourceListGetDescriptor = Ptr
        self.pfnWdfCmResourceListRemove = Ptr
        self.pfnWdfCmResourceListRemoveByDescriptor = Ptr
        self.pfnWdfStringCreate = Ptr
        self.pfnWdfStringGetUnicodeString = Ptr
        self.pfnWdfObjectAcquireLock = Ptr
        self.pfnWdfObjectReleaseLock = Ptr
        self.pfnWdfWaitLockCreate = Ptr
        self.pfnWdfWaitLockAcquire = Ptr
        self.pfnWdfWaitLockRelease = Ptr
        self.pfnWdfSpinLockCreate = Ptr
        self.pfnWdfSpinLockAcquire = Ptr
        self.pfnWdfSpinLockRelease = Ptr
        self.pfnWdfTimerCreate = Ptr
        self.pfnWdfTimerStart = Ptr
        self.pfnWdfTimerStop = Ptr
        self.pfnWdfTimerGetParentObject = Ptr
        self.pfnWdfUsbTargetDeviceCreate = Ptr
        self.pfnWdfUsbTargetDeviceRetrieveInformation = Ptr
        self.pfnWdfUsbTargetDeviceGetDeviceDescriptor = Ptr
        self.pfnWdfUsbTargetDeviceRetrieveConfigDescriptor = Ptr
        self.pfnWdfUsbTargetDeviceQueryString = Ptr
        self.pfnWdfUsbTargetDeviceAllocAndQueryString = Ptr
        self.pfnWdfUsbTargetDeviceFormatRequestForString = Ptr
        self.pfnWdfUsbTargetDeviceGetNumInterfaces = Ptr
        self.pfnWdfUsbTargetDeviceSelectConfig = Ptr
        self.pfnWdfUsbTargetDeviceWdmGetConfigurationHandle = Ptr
        self.pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber = Ptr
        self.pfnWdfUsbTargetDeviceSendControlTransferSynchronously = Ptr
        self.pfnWdfUsbTargetDeviceFormatRequestForControlTransfer = Ptr
        self.pfnWdfUsbTargetDeviceIsConnectedSynchronous = Ptr
        self.pfnWdfUsbTargetDeviceResetPortSynchronously = Ptr
        self.pfnWdfUsbTargetDeviceCyclePortSynchronously = Ptr
        self.pfnWdfUsbTargetDeviceFormatRequestForCyclePort = Ptr
        self.pfnWdfUsbTargetDeviceSendUrbSynchronously = Ptr
        self.pfnWdfUsbTargetDeviceFormatRequestForUrb = Ptr
        self.pfnWdfUsbTargetPipeGetInformation = Ptr
        self.pfnWdfUsbTargetPipeIsInEndpoint = Ptr
        self.pfnWdfUsbTargetPipeIsOutEndpoint = Ptr
        self.pfnWdfUsbTargetPipeGetType = Ptr
        self.pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck = Ptr
        self.pfnWdfUsbTargetPipeWriteSynchronously = Ptr
        self.pfnWdfUsbTargetPipeFormatRequestForWrite = Ptr
        self.pfnWdfUsbTargetPipeReadSynchronously = Ptr
        self.pfnWdfUsbTargetPipeFormatRequestForRead = Ptr
        self.pfnWdfUsbTargetPipeConfigContinuousReader = Ptr
        self.pfnWdfUsbTargetPipeAbortSynchronously = Ptr
        self.pfnWdfUsbTargetPipeFormatRequestForAbort = Ptr
        self.pfnWdfUsbTargetPipeResetSynchronously = Ptr
        self.pfnWdfUsbTargetPipeFormatRequestForReset = Ptr
        self.pfnWdfUsbTargetPipeSendUrbSynchronously = Ptr
        self.pfnWdfUsbTargetPipeFormatRequestForUrb = Ptr
        self.pfnWdfUsbInterfaceGetInterfaceNumber = Ptr
        self.pfnWdfUsbInterfaceGetNumEndpoints = Ptr
        self.pfnWdfUsbInterfaceGetDescriptor = Ptr
        self.pfnWdfUsbInterfaceSelectSetting = Ptr
        self.pfnWdfUsbInterfaceGetEndpointInformation = Ptr
        self.pfnWdfUsbTargetDeviceGetInterface = Ptr
        self.pfnWdfUsbInterfaceGetConfiguredSettingIndex = Ptr
        self.pfnWdfUsbInterfaceGetNumConfiguredPipes = Ptr
        self.pfnWdfUsbInterfaceGetConfiguredPipe = Ptr
        self.pfnWdfUsbTargetPipeWdmGetPipeHandle = Ptr
        self.pfnWdfVerifierDbgBreakPoint = Ptr
        self.pfnWdfVerifierKeBugCheck = Ptr
        self.pfnWdfWmiProviderCreate = Ptr
        self.pfnWdfWmiProviderGetDevice = Ptr
        self.pfnWdfWmiProviderIsEnabled = Ptr
        self.pfnWdfWmiProviderGetTracingHandle = Ptr
        self.unknown0 = Ptr * 13
        self.pfnWdfUsbInterfaceGetNumSettings = Ptr
        self.unknown1 = Ptr * 34
        self.pfnWdfUsbTargetDeviceCreateWithParameters = Ptr

.class public final Lnet/gotev/uploadservice/UploadNotificationConfig;
.super Ljava/lang/Object;
.source "UploadNotificationConfig.java"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lnet/gotev/uploadservice/UploadNotificationConfig;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private autoClearOnCancel:Z

.field private autoClearOnError:Z

.field private autoClearOnSuccess:Z

.field private cancelled:Ljava/lang/String;

.field private cancelledIconColorResourceID:I

.field private cancelledIconResourceID:I

.field private clearOnAction:Z

.field private clickIntent:Landroid/content/Intent;

.field private completed:Ljava/lang/String;

.field private completedIconColorResourceID:I

.field private completedIconResourceID:I

.field private error:Ljava/lang/String;

.field private errorIconColorResourceID:I

.field private errorIconResourceID:I

.field private iconColorResourceID:I

.field private iconResourceID:I

.field private inProgress:Ljava/lang/String;

.field private ringToneEnabled:Z

.field private title:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 352
    new-instance v0, Lnet/gotev/uploadservice/UploadNotificationConfig$1;

    invoke-direct {v0}, Lnet/gotev/uploadservice/UploadNotificationConfig$1;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadNotificationConfig;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 50
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    const v0, 0x1080055

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconResourceID:I

    .line 52
    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconResourceID:I

    .line 53
    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconResourceID:I

    .line 54
    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconResourceID:I

    .line 55
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconColorResourceID:I

    .line 56
    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconColorResourceID:I

    .line 57
    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconColorResourceID:I

    .line 58
    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconColorResourceID:I

    .line 59
    const-string v1, "File Upload"

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->title:Ljava/lang/String;

    .line 60
    const-string v1, "Uploading at [[UPLOAD_RATE]] ([[PROGRESS]])"

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->inProgress:Ljava/lang/String;

    .line 61
    const-string v1, "Upload completed successfully in [[ELAPSED_TIME]]"

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completed:Ljava/lang/String;

    .line 62
    const-string v1, "Error during upload"

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->error:Ljava/lang/String;

    .line 63
    const-string v1, "Upload cancelled"

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelled:Ljava/lang/String;

    .line 64
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnSuccess:Z

    .line 65
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnError:Z

    .line 66
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnCancel:Z

    .line 67
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clearOnAction:Z

    .line 68
    const/4 v0, 0x0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clickIntent:Landroid/content/Intent;

    .line 69
    const/4 v0, 0x1

    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->ringToneEnabled:Z

    .line 70
    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 3
    .param p1, "in"    # Landroid/os/Parcel;

    .line 393
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 394
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconResourceID:I

    .line 395
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconResourceID:I

    .line 396
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconResourceID:I

    .line 397
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconResourceID:I

    .line 398
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconColorResourceID:I

    .line 399
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconColorResourceID:I

    .line 400
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconColorResourceID:I

    .line 401
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconColorResourceID:I

    .line 402
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->title:Ljava/lang/String;

    .line 403
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->inProgress:Ljava/lang/String;

    .line 404
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completed:Ljava/lang/String;

    .line 405
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->error:Ljava/lang/String;

    .line 406
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelled:Ljava/lang/String;

    .line 407
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-ne v0, v2, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnSuccess:Z

    .line 408
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v0

    if-ne v0, v2, :cond_1

    const/4 v0, 0x1

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    :goto_1
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnError:Z

    .line 409
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v0

    if-ne v0, v2, :cond_2

    const/4 v0, 0x1

    goto :goto_2

    :cond_2
    const/4 v0, 0x0

    :goto_2
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnCancel:Z

    .line 410
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v0

    if-ne v0, v2, :cond_3

    const/4 v0, 0x1

    goto :goto_3

    :cond_3
    const/4 v0, 0x0

    :goto_3
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clearOnAction:Z

    .line 411
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v0

    if-ne v0, v2, :cond_4

    const/4 v1, 0x1

    :cond_4
    iput-boolean v1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->ringToneEnabled:Z

    .line 412
    const-class v0, Landroid/content/Intent;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Landroid/content/Intent;

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clickIntent:Landroid/content/Intent;

    .line 413
    return-void
.end method

.method synthetic constructor <init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/UploadNotificationConfig$1;)V
    .locals 0
    .param p1, "x0"    # Landroid/os/Parcel;
    .param p2, "x1"    # Lnet/gotev/uploadservice/UploadNotificationConfig$1;

    .line 15
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/UploadNotificationConfig;-><init>(Landroid/os/Parcel;)V

    return-void
.end method


# virtual methods
.method public describeContents()I
    .locals 1

    .line 367
    const/4 v0, 0x0

    return v0
.end method

.method final getCancelledIconColorResourceID()I
    .locals 1

    .line 299
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconColorResourceID:I

    return v0
.end method

.method final getCancelledIconResourceID()I
    .locals 1

    .line 283
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconResourceID:I

    return v0
.end method

.method final getCancelledMessage()Ljava/lang/String;
    .locals 1

    .line 319
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelled:Ljava/lang/String;

    return-object v0
.end method

.method final getCompletedIconColorResourceID()I
    .locals 1

    .line 291
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconColorResourceID:I

    return v0
.end method

.method final getCompletedIconResourceID()I
    .locals 1

    .line 275
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconResourceID:I

    return v0
.end method

.method final getCompletedMessage()Ljava/lang/String;
    .locals 1

    .line 311
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completed:Ljava/lang/String;

    return-object v0
.end method

.method final getErrorIconColorResourceID()I
    .locals 1

    .line 295
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconColorResourceID:I

    return v0
.end method

.method final getErrorIconResourceID()I
    .locals 1

    .line 279
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconResourceID:I

    return v0
.end method

.method final getErrorMessage()Ljava/lang/String;
    .locals 1

    .line 315
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->error:Ljava/lang/String;

    return-object v0
.end method

.method final getIconColorResourceID()I
    .locals 1

    .line 287
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconColorResourceID:I

    return v0
.end method

.method final getIconResourceID()I
    .locals 1

    .line 271
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconResourceID:I

    return v0
.end method

.method final getInProgressMessage()Ljava/lang/String;
    .locals 1

    .line 307
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->inProgress:Ljava/lang/String;

    return-object v0
.end method

.method final getPendingIntent(Landroid/content/Context;)Landroid/app/PendingIntent;
    .locals 3
    .param p1, "context"    # Landroid/content/Context;

    .line 343
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clickIntent:Landroid/content/Intent;

    const/high16 v1, 0x8000000

    if-nez v0, :cond_0

    .line 344
    const/4 v0, 0x0

    new-instance v2, Landroid/content/Intent;

    invoke-direct {v2}, Landroid/content/Intent;-><init>()V

    invoke-static {p1, v0, v2, v1}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object v0

    return-object v0

    .line 347
    :cond_0
    const/4 v2, 0x1

    invoke-static {p1, v2, v0, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object v0

    return-object v0
.end method

.method final getTitle()Ljava/lang/String;
    .locals 1

    .line 303
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->title:Ljava/lang/String;

    return-object v0
.end method

.method final isAutoClearOnCancel()Z
    .locals 1

    .line 331
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnCancel:Z

    return v0
.end method

.method final isAutoClearOnError()Z
    .locals 1

    .line 327
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnError:Z

    return v0
.end method

.method final isAutoClearOnSuccess()Z
    .locals 1

    .line 323
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnSuccess:Z

    return v0
.end method

.method final isClearOnAction()Z
    .locals 1

    .line 335
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clearOnAction:Z

    return v0
.end method

.method final isRingToneEnabled()Z
    .locals 1

    .line 339
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->ringToneEnabled:Z

    return v0
.end method

.method public final setAutoClearOnCancel(Z)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "clear"    # Z

    .line 234
    iput-boolean p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnCancel:Z

    .line 235
    return-object p0
.end method

.method public final setAutoClearOnError(Z)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "clear"    # Z

    .line 224
    iput-boolean p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnError:Z

    .line 225
    return-object p0
.end method

.method public final setAutoClearOnSuccess(Z)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "clear"    # Z

    .line 214
    iput-boolean p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnSuccess:Z

    .line 215
    return-object p0
.end method

.method public final setCancelledIcon(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 111
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconResourceID:I

    .line 112
    return-object p0
.end method

.method public final setCancelledIconColor(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 154
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconColorResourceID:I

    .line 155
    return-object p0
.end method

.method public final setCancelledMessage(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "message"    # Ljava/lang/String;

    .line 204
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelled:Ljava/lang/String;

    .line 205
    return-object p0
.end method

.method public final setClearOnAction(Z)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "clear"    # Z

    .line 244
    iput-boolean p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clearOnAction:Z

    .line 245
    return-object p0
.end method

.method public final setClickIntent(Landroid/content/Intent;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "clickIntent"    # Landroid/content/Intent;

    .line 255
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clickIntent:Landroid/content/Intent;

    .line 256
    return-object p0
.end method

.method public final setCompletedIcon(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 89
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconResourceID:I

    .line 90
    return-object p0
.end method

.method public final setCompletedIconColor(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 132
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconColorResourceID:I

    .line 133
    return-object p0
.end method

.method public final setCompletedMessage(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "message"    # Ljava/lang/String;

    .line 194
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completed:Ljava/lang/String;

    .line 195
    return-object p0
.end method

.method public final setErrorIcon(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 100
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconResourceID:I

    .line 101
    return-object p0
.end method

.method public final setErrorIconColor(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 143
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconColorResourceID:I

    .line 144
    return-object p0
.end method

.method public final setErrorMessage(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "message"    # Ljava/lang/String;

    .line 184
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->error:Ljava/lang/String;

    .line 185
    return-object p0
.end method

.method public final setIcon(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 78
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconResourceID:I

    .line 79
    return-object p0
.end method

.method public final setIconColor(I)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "resourceID"    # I

    .line 121
    iput p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconColorResourceID:I

    .line 122
    return-object p0
.end method

.method public final setInProgressMessage(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "message"    # Ljava/lang/String;

    .line 174
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->inProgress:Ljava/lang/String;

    .line 175
    return-object p0
.end method

.method public final setRingToneEnabled(Ljava/lang/Boolean;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 1
    .param p1, "enabled"    # Ljava/lang/Boolean;

    .line 266
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->ringToneEnabled:Z

    .line 267
    return-object p0
.end method

.method public final setTitle(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 0
    .param p1, "title"    # Ljava/lang/String;

    .line 164
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->title:Ljava/lang/String;

    .line 165
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2
    .param p1, "parcel"    # Landroid/os/Parcel;
    .param p2, "arg1"    # I

    .line 372
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 373
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 374
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 375
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 376
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->iconColorResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 377
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completedIconColorResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 378
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->errorIconColorResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 379
    iget v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelledIconColorResourceID:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 380
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->title:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 381
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->inProgress:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 382
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->completed:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 383
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->error:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 384
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->cancelled:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 385
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnSuccess:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 386
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnError:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 387
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->autoClearOnCancel:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 388
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clearOnAction:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 389
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->ringToneEnabled:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 390
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadNotificationConfig;->clickIntent:Landroid/content/Intent;

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 391
    return-void
.end method

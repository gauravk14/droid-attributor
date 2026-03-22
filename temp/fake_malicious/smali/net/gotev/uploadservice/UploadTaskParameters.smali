.class public final Lnet/gotev/uploadservice/UploadTaskParameters;
.super Ljava/lang/Object;
.source "UploadTaskParameters.java"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lnet/gotev/uploadservice/UploadTaskParameters;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private autoDeleteSuccessfullyUploadedFiles:Z

.field private files:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lnet/gotev/uploadservice/UploadFile;",
            ">;"
        }
    .end annotation
.end field

.field private id:Ljava/lang/String;

.field private maxRetries:I

.field private notificationConfig:Lnet/gotev/uploadservice/UploadNotificationConfig;

.field private serverUrl:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 34
    new-instance v0, Lnet/gotev/uploadservice/UploadTaskParameters$1;

    invoke-direct {v0}, Lnet/gotev/uploadservice/UploadTaskParameters$1;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadTaskParameters;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    .line 24
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->autoDeleteSuccessfullyUploadedFiles:Z

    .line 26
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->files:Ljava/util/ArrayList;

    .line 30
    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 3
    .param p1, "in"    # Landroid/os/Parcel;

    .line 57
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    .line 24
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->autoDeleteSuccessfullyUploadedFiles:Z

    .line 26
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->files:Ljava/util/ArrayList;

    .line 58
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->id:Ljava/lang/String;

    .line 59
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->serverUrl:Ljava/lang/String;

    .line 60
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    iput v1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    .line 61
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    const/4 v0, 0x1

    :cond_0
    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->autoDeleteSuccessfullyUploadedFiles:Z

    .line 62
    const-class v0, Lnet/gotev/uploadservice/UploadNotificationConfig;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadNotificationConfig;

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->notificationConfig:Lnet/gotev/uploadservice/UploadNotificationConfig;

    .line 63
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->files:Ljava/util/ArrayList;

    const-class v1, Lnet/gotev/uploadservice/UploadFile;

    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->readList(Ljava/util/List;Ljava/lang/ClassLoader;)V

    .line 64
    return-void
.end method

.method synthetic constructor <init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/UploadTaskParameters$1;)V
    .locals 0
    .param p1, "x0"    # Landroid/os/Parcel;
    .param p2, "x1"    # Lnet/gotev/uploadservice/UploadTaskParameters$1;

    .line 19
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/UploadTaskParameters;-><init>(Landroid/os/Parcel;)V

    return-void
.end method


# virtual methods
.method public addFile(Lnet/gotev/uploadservice/UploadFile;)V
    .locals 1
    .param p1, "file"    # Lnet/gotev/uploadservice/UploadFile;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;
        }
    .end annotation

    .line 73
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->files:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 74
    return-void
.end method

.method public describeContents()I
    .locals 1

    .line 68
    const/4 v0, 0x0

    return v0
.end method

.method public getFiles()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lnet/gotev/uploadservice/UploadFile;",
            ">;"
        }
    .end annotation

    .line 77
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->files:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getId()Ljava/lang/String;
    .locals 1

    .line 90
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->id:Ljava/lang/String;

    return-object v0
.end method

.method public getMaxRetries()I
    .locals 1

    .line 108
    iget v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    return v0
.end method

.method public getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;
    .locals 1

    .line 81
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->notificationConfig:Lnet/gotev/uploadservice/UploadNotificationConfig;

    return-object v0
.end method

.method public getServerUrl()Ljava/lang/String;
    .locals 1

    .line 99
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->serverUrl:Ljava/lang/String;

    return-object v0
.end method

.method public isAutoDeleteSuccessfullyUploadedFiles()Z
    .locals 1

    .line 121
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->autoDeleteSuccessfullyUploadedFiles:Z

    return v0
.end method

.method public setAutoDeleteSuccessfullyUploadedFiles(Z)Lnet/gotev/uploadservice/UploadTaskParameters;
    .locals 0
    .param p1, "autoDeleteSuccessfullyUploadedFiles"    # Z

    .line 125
    iput-boolean p1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->autoDeleteSuccessfullyUploadedFiles:Z

    .line 126
    return-object p0
.end method

.method public setId(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadTaskParameters;
    .locals 0
    .param p1, "id"    # Ljava/lang/String;

    .line 94
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->id:Ljava/lang/String;

    .line 95
    return-object p0
.end method

.method public setMaxRetries(I)Lnet/gotev/uploadservice/UploadTaskParameters;
    .locals 1
    .param p1, "maxRetries"    # I

    .line 112
    if-gez p1, :cond_0

    .line 113
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    goto :goto_0

    .line 115
    :cond_0
    iput p1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    .line 117
    :goto_0
    return-object p0
.end method

.method public setNotificationConfig(Lnet/gotev/uploadservice/UploadNotificationConfig;)Lnet/gotev/uploadservice/UploadTaskParameters;
    .locals 0
    .param p1, "notificationConfig"    # Lnet/gotev/uploadservice/UploadNotificationConfig;

    .line 85
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->notificationConfig:Lnet/gotev/uploadservice/UploadNotificationConfig;

    .line 86
    return-object p0
.end method

.method public setServerUrl(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadTaskParameters;
    .locals 0
    .param p1, "url"    # Ljava/lang/String;

    .line 103
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->serverUrl:Ljava/lang/String;

    .line 104
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2
    .param p1, "parcel"    # Landroid/os/Parcel;
    .param p2, "arg1"    # I

    .line 49
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->id:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 50
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->serverUrl:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 51
    iget v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->maxRetries:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 52
    iget-boolean v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->autoDeleteSuccessfullyUploadedFiles:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 53
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->notificationConfig:Lnet/gotev/uploadservice/UploadNotificationConfig;

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 54
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTaskParameters;->files:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeList(Ljava/util/List;)V

    .line 55
    return-void
.end method

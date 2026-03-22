.class public final Lnet/gotev/uploadservice/HttpUploadTaskParameters;
.super Ljava/lang/Object;
.source "HttpUploadTaskParameters.java"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lnet/gotev/uploadservice/HttpUploadTaskParameters;",
            ">;"
        }
    .end annotation
.end field

.field protected static final PARAM_HTTP_TASK_PARAMETERS:Ljava/lang/String; = "httpTaskParameters"


# instance fields
.field private customUserAgent:Ljava/lang/String;

.field private method:Ljava/lang/String;

.field private requestHeaders:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lnet/gotev/uploadservice/NameValue;",
            ">;"
        }
    .end annotation
.end field

.field private requestParameters:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lnet/gotev/uploadservice/NameValue;",
            ">;"
        }
    .end annotation
.end field

.field private usesFixedLengthStreamingMode:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 30
    new-instance v0, Lnet/gotev/uploadservice/HttpUploadTaskParameters$1;

    invoke-direct {v0}, Lnet/gotev/uploadservice/HttpUploadTaskParameters$1;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    const-string v0, "POST"

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->method:Ljava/lang/String;

    .line 20
    const/4 v0, 0x1

    iput-boolean v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->usesFixedLengthStreamingMode:Z

    .line 21
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestHeaders:Ljava/util/ArrayList;

    .line 22
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestParameters:Ljava/util/ArrayList;

    .line 26
    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 2
    .param p1, "in"    # Landroid/os/Parcel;

    .line 52
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    const-string v0, "POST"

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->method:Ljava/lang/String;

    .line 20
    const/4 v0, 0x1

    iput-boolean v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->usesFixedLengthStreamingMode:Z

    .line 21
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestHeaders:Ljava/util/ArrayList;

    .line 22
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestParameters:Ljava/util/ArrayList;

    .line 53
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->method:Ljava/lang/String;

    .line 54
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->customUserAgent:Ljava/lang/String;

    .line 55
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v1

    if-ne v1, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iput-boolean v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->usesFixedLengthStreamingMode:Z

    .line 56
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestHeaders:Ljava/util/ArrayList;

    const-class v1, Lnet/gotev/uploadservice/NameValue;

    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->readList(Ljava/util/List;Ljava/lang/ClassLoader;)V

    .line 57
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestParameters:Ljava/util/ArrayList;

    const-class v1, Lnet/gotev/uploadservice/NameValue;

    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->readList(Ljava/util/List;Ljava/lang/ClassLoader;)V

    .line 58
    return-void
.end method

.method synthetic constructor <init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/HttpUploadTaskParameters$1;)V
    .locals 0
    .param p1, "x0"    # Landroid/os/Parcel;
    .param p2, "x1"    # Lnet/gotev/uploadservice/HttpUploadTaskParameters$1;

    .line 14
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;-><init>(Landroid/os/Parcel;)V

    return-void
.end method


# virtual methods
.method public addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    .param p1, "name"    # Ljava/lang/String;
    .param p2, "value"    # Ljava/lang/String;

    .line 66
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestHeaders:Ljava/util/ArrayList;

    new-instance v1, Lnet/gotev/uploadservice/NameValue;

    const/4 v2, 0x1

    invoke-direct {v1, p1, p2, v2}, Lnet/gotev/uploadservice/NameValue;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 67
    return-void
.end method

.method public addRequestParameter(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    .param p1, "name"    # Ljava/lang/String;
    .param p2, "value"    # Ljava/lang/String;

    .line 70
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestParameters:Ljava/util/ArrayList;

    new-instance v1, Lnet/gotev/uploadservice/NameValue;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p2, v2}, Lnet/gotev/uploadservice/NameValue;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    return-void
.end method

.method public describeContents()I
    .locals 1

    .line 62
    const/4 v0, 0x0

    return v0
.end method

.method public getCustomUserAgent()Ljava/lang/String;
    .locals 1

    .line 101
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->customUserAgent:Ljava/lang/String;

    return-object v0
.end method

.method public getMethod()Ljava/lang/String;
    .locals 1

    .line 82
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->method:Ljava/lang/String;

    return-object v0
.end method

.method public getRequestHeaders()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lnet/gotev/uploadservice/NameValue;",
            ">;"
        }
    .end annotation

    .line 74
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestHeaders:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getRequestParameters()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lnet/gotev/uploadservice/NameValue;",
            ">;"
        }
    .end annotation

    .line 78
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestParameters:Ljava/util/ArrayList;

    return-object v0
.end method

.method public isCustomUserAgentDefined()Z
    .locals 2

    .line 105
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->customUserAgent:Ljava/lang/String;

    if-eqz v0, :cond_0

    const-string v1, ""

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public isUsesFixedLengthStreamingMode()Z
    .locals 1

    .line 92
    iget-boolean v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->usesFixedLengthStreamingMode:Z

    return v0
.end method

.method public setCustomUserAgent(Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadTaskParameters;
    .locals 0
    .param p1, "customUserAgent"    # Ljava/lang/String;

    .line 109
    iput-object p1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->customUserAgent:Ljava/lang/String;

    .line 110
    return-object p0
.end method

.method public setMethod(Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadTaskParameters;
    .locals 1
    .param p1, "method"    # Ljava/lang/String;

    .line 86
    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    if-lez v0, :cond_0

    .line 87
    iput-object p1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->method:Ljava/lang/String;

    .line 88
    :cond_0
    return-object p0
.end method

.method public setUsesFixedLengthStreamingMode(Z)Lnet/gotev/uploadservice/HttpUploadTaskParameters;
    .locals 0
    .param p1, "usesFixedLengthStreamingMode"    # Z

    .line 96
    iput-boolean p1, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->usesFixedLengthStreamingMode:Z

    .line 97
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1
    .param p1, "parcel"    # Landroid/os/Parcel;
    .param p2, "arg1"    # I

    .line 45
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->method:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 46
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->customUserAgent:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 47
    iget-boolean v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->usesFixedLengthStreamingMode:Z

    int-to-byte v0, v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 48
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestHeaders:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeList(Ljava/util/List;)V

    .line 49
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->requestParameters:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeList(Ljava/util/List;)V

    .line 50
    return-void
.end method

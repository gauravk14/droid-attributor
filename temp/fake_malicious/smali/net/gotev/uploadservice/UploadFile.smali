.class public Lnet/gotev/uploadservice/UploadFile;
.super Ljava/lang/Object;
.source "UploadFile.java"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lnet/gotev/uploadservice/UploadFile;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field protected final handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

.field protected final path:Ljava/lang/String;

.field private properties:Ljava/util/LinkedHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/LinkedHashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 100
    new-instance v0, Lnet/gotev/uploadservice/UploadFile$1;

    invoke-direct {v0}, Lnet/gotev/uploadservice/UploadFile$1;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadFile;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 2
    .param p1, "in"    # Landroid/os/Parcel;

    .line 125
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    .line 126
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->path:Ljava/lang/String;

    .line 127
    invoke-virtual {p1}, Landroid/os/Parcel;->readSerializable()Ljava/io/Serializable;

    move-result-object v0

    check-cast v0, Ljava/util/LinkedHashMap;

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    .line 130
    :try_start_0
    invoke-static {}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;->getInstance()Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadFile;->path:Ljava/lang/String;

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;->get(Ljava/lang/String;)Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 133
    nop

    .line 134
    return-void

    .line 131
    :catch_0
    move-exception v0

    .line 132
    .local v0, "exc":Ljava/lang/Exception;
    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1
.end method

.method synthetic constructor <init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/UploadFile$1;)V
    .locals 0
    .param p1, "x0"    # Landroid/os/Parcel;
    .param p2, "x1"    # Lnet/gotev/uploadservice/UploadFile$1;

    .line 20
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/UploadFile;-><init>(Landroid/os/Parcel;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 3
    .param p1, "path"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;
        }
    .end annotation

    .line 33
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    .line 35
    if-eqz p1, :cond_1

    const-string v0, ""

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    .line 39
    invoke-static {}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;->getInstance()Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;

    move-result-object v0

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;->isSupported(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 42
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadFile;->path:Ljava/lang/String;

    .line 45
    :try_start_0
    invoke-static {}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;->getInstance()Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;

    move-result-object v0

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandlerFactory;->get(Ljava/lang/String;)Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    nop

    .line 49
    return-void

    .line 46
    :catch_0
    move-exception v0

    .line 47
    .local v0, "exc":Ljava/lang/Exception;
    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1

    .line 40
    .end local v0    # "exc":Ljava/lang/Exception;
    :cond_0
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Unsupported scheme: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 36
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Please specify a file path!"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public describeContents()I
    .locals 1

    .line 115
    const/4 v0, 0x0

    return v0
.end method

.method public final getContentType(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .param p1, "context"    # Landroid/content/Context;

    .line 77
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

    invoke-interface {v0, p1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;->getContentType(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getName(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .param p1, "context"    # Landroid/content/Context;

    .line 86
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

    invoke-interface {v0, p1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;->getName(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getPath()Ljava/lang/String;
    .locals 1

    .line 95
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->path:Ljava/lang/String;

    return-object v0
.end method

.method public getProperty(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p1, "key"    # Ljava/lang/String;

    .line 152
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    return-object v0
.end method

.method public getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p1, "key"    # Ljava/lang/String;
    .param p2, "defaultValue"    # Ljava/lang/String;

    .line 162
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 164
    .local v0, "val":Ljava/lang/String;
    if-nez v0, :cond_0

    .line 165
    move-object v0, p2

    .line 168
    :cond_0
    return-object v0
.end method

.method public final getStream(Landroid/content/Context;)Ljava/io/InputStream;
    .locals 1
    .param p1, "context"    # Landroid/content/Context;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;
        }
    .end annotation

    .line 68
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

    invoke-interface {v0, p1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;->getInputStream(Landroid/content/Context;)Ljava/io/InputStream;

    move-result-object v0

    return-object v0
.end method

.method public length(Landroid/content/Context;)J
    .locals 2
    .param p1, "context"    # Landroid/content/Context;

    .line 57
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->handler:Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;

    invoke-interface {v0, p1}, Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;->getLength(Landroid/content/Context;)J

    move-result-wide v0

    return-wide v0
.end method

.method public setProperty(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1
    .param p1, "key"    # Ljava/lang/String;
    .param p2, "value"    # Ljava/lang/String;

    .line 143
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1, p2}, Ljava/util/LinkedHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    return-void
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1
    .param p1, "parcel"    # Landroid/os/Parcel;
    .param p2, "arg1"    # I

    .line 120
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->path:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 121
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadFile;->properties:Ljava/util/LinkedHashMap;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeSerializable(Ljava/io/Serializable;)V

    .line 122
    return-void
.end method

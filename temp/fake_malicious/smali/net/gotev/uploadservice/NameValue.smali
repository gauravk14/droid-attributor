.class public final Lnet/gotev/uploadservice/NameValue;
.super Ljava/lang/Object;
.source "NameValue.java"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lnet/gotev/uploadservice/NameValue;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final name:Ljava/lang/String;

.field private final value:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 49
    new-instance v0, Lnet/gotev/uploadservice/NameValue$1;

    invoke-direct {v0}, Lnet/gotev/uploadservice/NameValue$1;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/NameValue;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 1
    .param p1, "in"    # Landroid/os/Parcel;

    .line 73
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 74
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/NameValue;->name:Ljava/lang/String;

    .line 75
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/NameValue;->value:Ljava/lang/String;

    .line 76
    return-void
.end method

.method synthetic constructor <init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/NameValue$1;)V
    .locals 0
    .param p1, "x0"    # Landroid/os/Parcel;
    .param p2, "x1"    # Lnet/gotev/uploadservice/NameValue$1;

    .line 12
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/NameValue;-><init>(Landroid/os/Parcel;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 3
    .param p1, "name"    # Ljava/lang/String;
    .param p2, "value"    # Ljava/lang/String;
    .param p3, "asciiOnly"    # Z

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    if-eqz p3, :cond_1

    invoke-static {p1}, Lnet/gotev/uploadservice/NameValue;->isAllASCII(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p2}, Lnet/gotev/uploadservice/NameValue;->isAllASCII(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 19
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Header "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " must be ASCII only! Read http://stackoverflow.com/a/4410331"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 21
    :cond_1
    :goto_0
    iput-object p1, p0, Lnet/gotev/uploadservice/NameValue;->name:Ljava/lang/String;

    .line 22
    iput-object p2, p0, Lnet/gotev/uploadservice/NameValue;->value:Ljava/lang/String;

    .line 23
    return-void
.end method

.method private static isAllASCII(Ljava/lang/String;)Z
    .locals 4
    .param p0, "input"    # Ljava/lang/String;

    .line 79
    if-eqz p0, :cond_3

    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_2

    .line 82
    :cond_0
    const/4 v0, 0x1

    .line 83
    .local v0, "isASCII":Z
    const/4 v1, 0x0

    .local v1, "i":I
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    if-ge v1, v2, :cond_2

    .line 84
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v2

    .line 85
    .local v2, "c":I
    const/16 v3, 0x7f

    if-le v2, v3, :cond_1

    .line 86
    const/4 v0, 0x0

    .line 87
    goto :goto_1

    .line 83
    .end local v2    # "c":I
    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 90
    .end local v1    # "i":I
    :cond_2
    :goto_1
    return v0

    .line 80
    .end local v0    # "isASCII":Z
    :cond_3
    :goto_2
    const/4 v0, 0x0

    return v0
.end method


# virtual methods
.method public describeContents()I
    .locals 1

    .line 64
    const/4 v0, 0x0

    return v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3
    .param p1, "object"    # Ljava/lang/Object;

    .line 37
    instance-of v0, p1, Lnet/gotev/uploadservice/NameValue;

    if-eqz v0, :cond_1

    .line 38
    move-object v0, p1

    check-cast v0, Lnet/gotev/uploadservice/NameValue;

    .line 39
    .local v0, "other":Lnet/gotev/uploadservice/NameValue;
    iget-object v1, p0, Lnet/gotev/uploadservice/NameValue;->name:Ljava/lang/String;

    iget-object v2, v0, Lnet/gotev/uploadservice/NameValue;->name:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v1, p0, Lnet/gotev/uploadservice/NameValue;->value:Ljava/lang/String;

    iget-object v2, v0, Lnet/gotev/uploadservice/NameValue;->value:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    move v0, v1

    .line 40
    .local v0, "areEqual":Z
    goto :goto_1

    .line 41
    .end local v0    # "areEqual":Z
    :cond_1
    const/4 v0, 0x0

    .line 44
    .restart local v0    # "areEqual":Z
    :goto_1
    return v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    .line 26
    iget-object v0, p0, Lnet/gotev/uploadservice/NameValue;->name:Ljava/lang/String;

    return-object v0
.end method

.method public final getValue()Ljava/lang/String;
    .locals 1

    .line 30
    iget-object v0, p0, Lnet/gotev/uploadservice/NameValue;->value:Ljava/lang/String;

    return-object v0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1
    .param p1, "parcel"    # Landroid/os/Parcel;
    .param p2, "arg1"    # I

    .line 69
    iget-object v0, p0, Lnet/gotev/uploadservice/NameValue;->name:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 70
    iget-object v0, p0, Lnet/gotev/uploadservice/NameValue;->value:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 71
    return-void
.end method

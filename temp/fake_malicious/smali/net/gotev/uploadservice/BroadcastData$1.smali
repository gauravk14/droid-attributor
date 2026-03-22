.class final Lnet/gotev/uploadservice/BroadcastData$1;
.super Ljava/lang/Object;
.source "BroadcastData.java"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnet/gotev/uploadservice/BroadcastData;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Landroid/os/Parcelable$Creator<",
        "Lnet/gotev/uploadservice/BroadcastData;",
        ">;"
    }
.end annotation


# direct methods
.method constructor <init>()V
    .locals 0

    .line 40
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public bridge synthetic createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 0

    .line 40
    invoke-virtual {p0, p1}, Lnet/gotev/uploadservice/BroadcastData$1;->createFromParcel(Landroid/os/Parcel;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object p1

    return-object p1
.end method

.method public createFromParcel(Landroid/os/Parcel;)Lnet/gotev/uploadservice/BroadcastData;
    .locals 2
    .param p1, "in"    # Landroid/os/Parcel;

    .line 43
    new-instance v0, Lnet/gotev/uploadservice/BroadcastData;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Lnet/gotev/uploadservice/BroadcastData;-><init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/BroadcastData$1;)V

    return-object v0
.end method

.method public bridge synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 40
    invoke-virtual {p0, p1}, Lnet/gotev/uploadservice/BroadcastData$1;->newArray(I)[Lnet/gotev/uploadservice/BroadcastData;

    move-result-object p1

    return-object p1
.end method

.method public newArray(I)[Lnet/gotev/uploadservice/BroadcastData;
    .locals 1
    .param p1, "size"    # I

    .line 48
    new-array v0, p1, [Lnet/gotev/uploadservice/BroadcastData;

    return-object v0
.end method

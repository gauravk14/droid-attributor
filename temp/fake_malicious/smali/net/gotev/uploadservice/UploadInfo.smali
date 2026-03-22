.class public Lnet/gotev/uploadservice/UploadInfo;
.super Ljava/lang/Object;
.source "UploadInfo.java"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lnet/gotev/uploadservice/UploadInfo;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private currentTime:J

.field private numberOfRetries:I

.field private startTime:J

.field private successfullyUploadedFiles:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private totalBytes:J

.field private totalFiles:I

.field private uploadId:Ljava/lang/String;

.field private uploadedBytes:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 51
    new-instance v0, Lnet/gotev/uploadservice/UploadInfo$1;

    invoke-direct {v0}, Lnet/gotev/uploadservice/UploadInfo$1;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadInfo;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 2
    .param p1, "in"    # Landroid/os/Parcel;

    .line 76
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    .line 77
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadId:Ljava/lang/String;

    .line 78
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->startTime:J

    .line 79
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->currentTime:J

    .line 80
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    .line 81
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalBytes:J

    .line 82
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadInfo;->numberOfRetries:I

    .line 83
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    iput v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalFiles:I

    .line 84
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readStringList(Ljava/util/List;)V

    .line 85
    return-void
.end method

.method synthetic constructor <init>(Landroid/os/Parcel;Lnet/gotev/uploadservice/UploadInfo$1;)V
    .locals 0
    .param p1, "x0"    # Landroid/os/Parcel;
    .param p2, "x1"    # Lnet/gotev/uploadservice/UploadInfo$1;

    .line 14
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/UploadInfo;-><init>(Landroid/os/Parcel;)V

    return-void
.end method

.method protected constructor <init>(Ljava/lang/String;)V
    .locals 2
    .param p1, "uploadId"    # Ljava/lang/String;

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    .line 26
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadId:Ljava/lang/String;

    .line 27
    const-wide/16 v0, 0x0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->startTime:J

    .line 28
    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->currentTime:J

    .line 29
    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    .line 30
    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalBytes:J

    .line 31
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadInfo;->numberOfRetries:I

    .line 32
    iput v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalFiles:I

    .line 33
    return-void
.end method

.method protected constructor <init>(Ljava/lang/String;JJJILjava/util/List;I)V
    .locals 2
    .param p1, "uploadId"    # Ljava/lang/String;
    .param p2, "startTime"    # J
    .param p4, "uploadedBytes"    # J
    .param p6, "totalBytes"    # J
    .param p8, "numberOfRetries"    # I
    .param p10, "totalFiles"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "JJJI",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;I)V"
        }
    .end annotation

    .line 36
    .local p9, "uploadedFiles":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    .line 37
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadId:Ljava/lang/String;

    .line 38
    iput-wide p2, p0, Lnet/gotev/uploadservice/UploadInfo;->startTime:J

    .line 39
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    invoke-virtual {v0}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->currentTime:J

    .line 40
    iput-wide p4, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    .line 41
    iput-wide p6, p0, Lnet/gotev/uploadservice/UploadInfo;->totalBytes:J

    .line 42
    iput p8, p0, Lnet/gotev/uploadservice/UploadInfo;->numberOfRetries:I

    .line 43
    iput p10, p0, Lnet/gotev/uploadservice/UploadInfo;->totalFiles:I

    .line 45
    if-eqz p9, :cond_0

    invoke-interface {p9}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    .line 46
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    invoke-virtual {v0, p9}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 47
    :cond_0
    return-void
.end method


# virtual methods
.method public describeContents()I
    .locals 1

    .line 89
    const/4 v0, 0x0

    return v0
.end method

.method public getElapsedTime()J
    .locals 4

    .line 113
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->currentTime:J

    iget-wide v2, p0, Lnet/gotev/uploadservice/UploadInfo;->startTime:J

    sub-long/2addr v0, v2

    return-wide v0
.end method

.method public getElapsedTimeString()Ljava/lang/String;
    .locals 5

    .line 122
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadInfo;->getElapsedTime()J

    move-result-wide v0

    const-wide/16 v2, 0x3e8

    div-long/2addr v0, v2

    long-to-int v1, v0

    .line 124
    .local v1, "elapsedSeconds":I
    if-nez v1, :cond_0

    .line 125
    const-string v0, "0s"

    return-object v0

    .line 127
    :cond_0
    div-int/lit8 v0, v1, 0x3c

    .line 128
    .local v0, "minutes":I
    mul-int/lit8 v2, v0, 0x3c

    sub-int/2addr v1, v2

    .line 130
    const-string v2, "s"

    if-nez v0, :cond_1

    .line 131
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2

    .line 134
    :cond_1
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v4, "m "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2
.end method

.method public getNumberOfRetries()I
    .locals 1

    .line 211
    iget v0, p0, Lnet/gotev/uploadservice/UploadInfo;->numberOfRetries:I

    return v0
.end method

.method public getProgressPercent()I
    .locals 6

    .line 199
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalBytes:J

    const-wide/16 v2, 0x0

    cmp-long v4, v0, v2

    if-nez v4, :cond_0

    .line 200
    const/4 v0, 0x0

    return v0

    .line 202
    :cond_0
    iget-wide v2, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    const-wide/16 v4, 0x64

    mul-long v2, v2, v4

    div-long/2addr v2, v0

    long-to-int v0, v2

    return v0
.end method

.method public getStartTime()J
    .locals 2

    .line 105
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->startTime:J

    return-wide v0
.end method

.method public getSuccessfullyUploadedFiles()Ljava/util/ArrayList;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 175
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    return-object v0
.end method

.method public getTotalBytes()J
    .locals 2

    .line 191
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalBytes:J

    return-wide v0
.end method

.method public getTotalFiles()I
    .locals 1

    .line 219
    iget v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalFiles:I

    return v0
.end method

.method public getUploadId()Ljava/lang/String;
    .locals 1

    .line 97
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadId:Ljava/lang/String;

    return-object v0
.end method

.method public getUploadRate()D
    .locals 8

    .line 142
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadInfo;->getElapsedTime()J

    move-result-wide v0

    .line 145
    .local v0, "elapsedTime":J
    const-wide/16 v2, 0x3e8

    cmp-long v4, v0, v2

    if-gez v4, :cond_0

    .line 146
    const-wide/16 v2, 0x0

    return-wide v2

    .line 148
    :cond_0
    iget-wide v4, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    long-to-double v4, v4

    const-wide/high16 v6, 0x4090000000000000L    # 1024.0

    invoke-static {v4, v5}, Ljava/lang/Double;->isNaN(D)Z

    div-double/2addr v4, v6

    const-wide/high16 v6, 0x4020000000000000L    # 8.0

    mul-double v4, v4, v6

    div-long v2, v0, v2

    long-to-double v2, v2

    invoke-static {v2, v3}, Ljava/lang/Double;->isNaN(D)Z

    div-double/2addr v4, v2

    return-wide v4
.end method

.method public getUploadRateString()Ljava/lang/String;
    .locals 5

    .line 157
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadInfo;->getUploadRate()D

    move-result-wide v0

    .line 159
    .local v0, "uploadRate":D
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    cmpg-double v4, v0, v2

    if-gez v4, :cond_0

    .line 160
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-wide v3, 0x408f400000000000L    # 1000.0

    mul-double v3, v3, v0

    double-to-int v3, v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " bit/s"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2

    .line 162
    :cond_0
    const-wide/high16 v2, 0x4090000000000000L    # 1024.0

    cmpl-double v4, v0, v2

    if-ltz v4, :cond_1

    .line 163
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    div-double v2, v0, v2

    double-to-int v2, v2

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, " Mbit/s"

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2

    .line 167
    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    double-to-int v3, v0

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " Kbit/s"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    return-object v2
.end method

.method public getUploadedBytes()J
    .locals 2

    .line 183
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    return-wide v0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2
    .param p1, "parcel"    # Landroid/os/Parcel;
    .param p2, "arg1"    # I

    .line 66
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadId:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 67
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->startTime:J

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 68
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->currentTime:J

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 69
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->uploadedBytes:J

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 70
    iget-wide v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalBytes:J

    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 71
    iget v0, p0, Lnet/gotev/uploadservice/UploadInfo;->numberOfRetries:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 72
    iget v0, p0, Lnet/gotev/uploadservice/UploadInfo;->totalFiles:I

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 73
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadInfo;->successfullyUploadedFiles:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeStringList(Ljava/util/List;)V

    .line 74
    return-void
.end method

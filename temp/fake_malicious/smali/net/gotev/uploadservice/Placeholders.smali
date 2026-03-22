.class public Lnet/gotev/uploadservice/Placeholders;
.super Ljava/lang/Object;
.source "Placeholders.java"


# static fields
.field public static final ELAPSED_TIME:Ljava/lang/String; = "[[ELAPSED_TIME]]"

.field public static final PROGRESS:Ljava/lang/String; = "[[PROGRESS]]"

.field public static final TOTAL_FILES:Ljava/lang/String; = "[[TOTAL_FILES]]"

.field public static final UPLOADED_FILES:Ljava/lang/String; = "[[UPLOADED_FILES]]"

.field public static final UPLOAD_RATE:Ljava/lang/String; = "[[UPLOAD_RATE]]"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;
    .locals 3
    .param p0, "string"    # Ljava/lang/String;
    .param p1, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;

    .line 45
    if-eqz p0, :cond_1

    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getElapsedTimeString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "[[ELAPSED_TIME]]"

    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v0

    .line 50
    .local v0, "tmp":Ljava/lang/String;
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getProgressPercent()I

    move-result v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, "%"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "[[PROGRESS]]"

    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v0

    .line 51
    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getUploadRateString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "[[UPLOAD_RATE]]"

    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v0

    .line 52
    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getSuccessfullyUploadedFiles()Ljava/util/ArrayList;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    move-result-object v1

    const-string v2, "[[UPLOADED_FILES]]"

    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v0

    .line 53
    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getTotalFiles()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    move-result-object v1

    const-string v2, "[[TOTAL_FILES]]"

    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v0

    .line 55
    return-object v0

    .line 46
    .end local v0    # "tmp":Ljava/lang/String;
    :cond_1
    :goto_0
    const-string v0, ""

    return-object v0
.end method

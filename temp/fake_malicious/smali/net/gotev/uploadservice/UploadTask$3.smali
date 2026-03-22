.class Lnet/gotev/uploadservice/UploadTask$3;
.super Ljava/lang/Object;
.source "UploadTask.java"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lnet/gotev/uploadservice/UploadTask;->broadcastCancelled()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lnet/gotev/uploadservice/UploadTask;

.field final synthetic val$delegate:Lnet/gotev/uploadservice/UploadStatusDelegate;

.field final synthetic val$uploadInfo:Lnet/gotev/uploadservice/UploadInfo;


# direct methods
.method constructor <init>(Lnet/gotev/uploadservice/UploadTask;Lnet/gotev/uploadservice/UploadStatusDelegate;Lnet/gotev/uploadservice/UploadInfo;)V
    .locals 0
    .param p1, "this$0"    # Lnet/gotev/uploadservice/UploadTask;

    .line 323
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadTask$3;->this$0:Lnet/gotev/uploadservice/UploadTask;

    iput-object p2, p0, Lnet/gotev/uploadservice/UploadTask$3;->val$delegate:Lnet/gotev/uploadservice/UploadStatusDelegate;

    iput-object p3, p0, Lnet/gotev/uploadservice/UploadTask$3;->val$uploadInfo:Lnet/gotev/uploadservice/UploadInfo;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .line 326
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask$3;->val$delegate:Lnet/gotev/uploadservice/UploadStatusDelegate;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask$3;->this$0:Lnet/gotev/uploadservice/UploadTask;

    iget-object v1, v1, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask$3;->val$uploadInfo:Lnet/gotev/uploadservice/UploadInfo;

    invoke-interface {v0, v1, v2}, Lnet/gotev/uploadservice/UploadStatusDelegate;->onCancelled(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;)V

    .line 327
    return-void
.end method

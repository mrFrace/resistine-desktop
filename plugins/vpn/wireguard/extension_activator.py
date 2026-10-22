import logging
import time
from Foundation import NSObject, NSOperationQueue
from SystemExtensions import OSSystemExtensionRequest, OSSystemExtensionManager

logger = logging.getLogger(__name__)

class ExtensionActivator(NSObject):
    def request_didFinishWithResult_(self, request, result):
        logger.info(f"✅ [Activator] Finished. Result code: {result}")

    def request_didFailWithError_(self, request, error):
        self.error = str(error.localizedDescription())
        logger.error(f"❌ [Activator] Failed: {self.error}")

    def requestNeedsUserApproval_(self, request):
        self.needs_approval = True
        logger.info("⚠️ [Activator] Needs User Approval in System Settings!")

    def request_actionForReplacingExtension_withExtension_(self, request, existing, extension):
        logger.info("🔄 [Activator] Replacing existing extension")
        return 1 # Replace

def run_activation(bundle_id):
    """Fire the activation request. This must be called from a context where the NSRunLoop is running (like the main UI app)."""
    logger.info(f"🚀 [Activator] Requesting activation for {bundle_id}")
    
    activator = ExtensionActivator.alloc().init()
    activator.error = None  # set by the delegate callbacks (main queue)
    activator.needs_approval = False
    
    # Use the main queue's underlying dispatch queue
    queue = NSOperationQueue.mainQueue().underlyingQueue()
    request = OSSystemExtensionRequest.activationRequestForExtension_queue_(bundle_id, queue)
    
    request.setDelegate_(activator)
    
    manager = OSSystemExtensionManager.sharedManager()
    manager.submitRequest_(request)
    
    # We must keep 'activator' alive for the delegate callbacks.
    # In a full app, we'd store it in a singleton or app delegate.
    # For this script, we'll return it so the caller holds a reference.
    return activator

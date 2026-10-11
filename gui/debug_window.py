import sys
import tkinter as tk


class DebugWindow:
    """Debug window to show print statements and logs in real-time"""

    def __init__(self, parent):
        self.parent = parent
        self.debug_window = None
        self.text_widget = None
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

    def create_debug_window(self):
        """Create the debug window"""
        self.debug_window = tk.Toplevel(self.parent)
        self.debug_window.title("Phoenix Debug Output")
        self.debug_window.geometry("800x600")

        # Create text widget WITHOUT scroll
        self.text_widget = tk.Text(self.debug_window, wrap=tk.WORD)
        self.text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add buttons
        button_frame = tk.Frame(self.debug_window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        clear_button = tk.Button(button_frame, text="Clear", command=self.clear_output)
        clear_button.pack(side=tk.LEFT, padx=5)

        save_button = tk.Button(button_frame, text="Save Log", command=self.save_log)
        save_button.pack(side=tk.LEFT, padx=5)

        # Redirect stdout and stderr
        self.redirect_output()

        # Add initial message
        self.log_message("=== RESISTINE DEBUG WINDOW ===\n")
        self.log_message("All print statements and logs will appear here.\n")
        self.log_message("=" * 50 + "\n")

    def redirect_output(self):
        """Redirect stdout and stderr to the debug window"""

        class DebugOutput:
            def __init__(self, debug_window):
                self.debug_window = debug_window

            def write(self, text):
                if text.strip():  # Only log non-empty text
                    self.debug_window.log_message(text)
                self.debug_window.original_stdout.write(text)

            def flush(self):
                self.debug_window.original_stdout.flush()

        sys.stdout = DebugOutput(self)
        sys.stderr = DebugOutput(self)

    def log_message(self, message):
        """Add a message to the debug window"""
        if self.text_widget:
            try:
                # Ensure we're operating on the correct widget
                if self.text_widget.winfo_exists():
                    # Temporarily disable state to allow insertion
                    current_state = self.text_widget.cget('state')
                    self.text_widget.config(state='normal')
                    
                    # Insert at the end of THIS specific widget
                    self.text_widget.insert('end', message)
                    self.text_widget.see('end')  # Auto-scroll to bottom
                    
                    # Restore state
                    self.text_widget.config(state=current_state)
                    
                    # Force update to this widget only
                    self.text_widget.update_idletasks()
            except tk.TclError:
                # Widget was destroyed, stop trying to log
                pass

    def clear_output(self):
        """Clear the debug output"""
        if self.text_widget:
            self.text_widget.delete(1.0, tk.END)

    def save_log(self):
        """Save the debug output to a file"""
        if self.text_widget:
            content = self.text_widget.get(1.0, tk.END)
            try:
                import datetime

                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"resistine_debug_{timestamp}.log"

                with open(filename, "w") as f:
                    f.write(content)

                self.log_message(f"Log saved to: {filename}\n")
            except Exception as e:
                self.log_message(f"Error saving log: {e}\n")

    def restore_output(self):
        """Restore original stdout and stderr"""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

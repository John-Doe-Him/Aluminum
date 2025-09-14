
import os
import sys
from PyQt5.QtGui import QIcon # type: ignore
from PyQt5.QtWidgets import QApplication # type: ignore
from PyQt5.QtCore import QSize # type: ignore

def set_aluminum_browser_icon(app):
    """
    Set the icon for the Aluminum web browser application.
    
    This function loads and sets a custom icon for the Aluminum browser,
    ensuring a professional and visually appealing appearance across
    different operating systems and display contexts.
    
    Args:
        app (QApplication): The main application instance.
    """
    
    # Define the path to the icon file
    # Assuming the icon is stored in a 'resources' folder at the root of the project
    icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'resources', 'AppIcon.ico')
    
    # Ensure the icon file exists
    if not os.path.exists(icon_path):
        print(f"Warning: Icon file not found at {icon_path}")
        return
    
    # Create a QIcon object from the icon file
    app_icon = QIcon(icon_path)
    
    # Set the application icon
    app.setWindowIcon(app_icon)
    
    # Define multiple sizes for different contexts
    icon_sizes = [16, 24, 32, 48, 64, 128, 256]
    
    # Add the icon in multiple sizes for better scaling and appearance
    for size in icon_sizes:
        app_icon.addFile(icon_path, QSize(size, size))
    
    # Set the taskbar icon (Windows-specific)
    if sys.platform.startswith('win'):
        import ctypes
        app_id = 'com.dwk.aluminum.integrate'  # Unique app id
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    
    # Set the dock icon (macOS-specific)
    if sys.platform == 'darwin':
        app.setWindowIcon(app_icon)  # This also sets the dock icon on macOS
    
    # Log the successful icon setting
    print("Aluminum browser icon has been successfully set.")

if __name__ == '__main__':
    # Create the application instance
    aluminum_app = QApplication(sys.argv)
    
    # Set the application icon
    set_aluminum_browser_icon(aluminum_app)
    
    # Start the application event loop
    sys.exit(aluminum_app.exec_())

# Additional helper function for icon management
def get_icon_path_for_theme(icon_name, theme='light'):
    """
    Get the appropriate icon path based on the current theme.
    
    This function allows for theme-specific icons, improving the
    user experience by providing icons that match the overall UI theme.
    
    Args:
        icon_name (str): The base name of the icon file.
        theme (str): The current theme ('light' or 'dark').
    
    Returns:
        str: The full path to the theme-appropriate icon.
    """
    base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'resources', 'icons')
    theme_path = os.path.join(base_path, theme)
    icon_path = os.path.join(theme_path, f"{icon_name}.png")
    
    if os.path.exists(icon_path):
        return icon_path
    else:
        # Fallback to default icon if theme-specific icon is not found
        return os.path.join(base_path, f"{icon_name}.png")

# Function to update icons when theme changes
def update_icons_for_theme(main_window, theme):
    """
    Update all icons in the application when the theme changes.
    
    This function should be called whenever the application theme
    is switched between light and dark modes.
    
    Args:
        main_window (QMainWindow): The main window of the application.
        theme (str): The new theme ('light' or 'dark').
    """
    # Update main application icon
    set_aluminum_browser_icon(QApplication.instance())
    
    # Update toolbar icons
    toolbar = main_window.findChild(QToolBar) # type: ignore
    if toolbar:
        for action in toolbar.actions():
            icon_name = action.property('icon_name')
            if icon_name:
                new_icon_path = get_icon_path_for_theme(icon_name, theme)
                action.setIcon(QIcon(new_icon_path))
    
    # Update other UI elements with icons
    # ... (implement updates for other parts of the UI)
    
    print(f"Icons updated for {theme} theme.")

# Function to generate a high-quality icon set
def generate_icon_set(base_icon_path, output_folder, sizes=[16, 24, 32, 48, 64, 128, 256]):
    """
    Generate a set of icons in various sizes from a base high-resolution icon.
    
    This function creates a full set of icons for different contexts and
    resolutions, ensuring the application looks great on all platforms.
    
    Args:
        base_icon_path (str): Path to the high-resolution base icon.
        output_folder (str): Folder to save the generated icons.
        sizes (list): List of icon sizes to generate.
    """
    from PIL import Image
    
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    base_icon = Image.open(base_icon_path)
    
    for size in sizes:
        resized_icon = base_icon.resize((size, size), Image.LANCZOS)
        output_path = os.path.join(output_folder, f"icon_{size}x{size}.png")
        resized_icon.save(output_path, "PNG")
    
    print(f"Icon set generated in {output_folder}")

# Example usage of the icon set generator
# generate_icon_set('path/to/high_res_icon.png', 'path/to/output/folder')

# This extensive implementation provides a robust and flexible system
# for managing the Aluminum web browser's iconography across different
# platforms, themes, and display contexts. It includes functions for
# setting the main application icon, handling theme-specific icons,
# updating icons when the theme changes, and even generating icon sets
# from a high-resolution base image. This approach ensures a consistent
# and professional appearance for the Aluminum browser in various
# environments and use cases.

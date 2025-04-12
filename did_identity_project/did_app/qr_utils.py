"""
Utilities for QR code generation
"""
import io
import base64
import qrcode
from qrcode.image.svg import SvgImage

def generate_qr_code(data, as_image=False):
    """
    Generate QR code from data
    
    Args:
        data: String data to encode in the QR code
        as_image: If True, returns the QR code as a PIL Image object,
                 otherwise returns a base64 encoded string
    
    Returns:
        base64 encoded string of the QR code or PIL Image object
    """
    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # Add data to the QR code
    qr.add_data(data)
    qr.make(fit=True)
    
    # Create an image from the QR Code instance
    img = qr.make_image(fill_color="black", back_color="white")
    
    if as_image:
        return img
    
    # Convert to base64 for embedding in HTML
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def generate_svg_qr_code(data):
    """
    Generate SVG QR code from data
    
    Args:
        data: String data to encode in the QR code
    
    Returns:
        SVG string of the QR code
    """
    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
        image_factory=SvgImage
    )
    
    # Add data to the QR code
    qr.add_data(data)
    qr.make(fit=True)
    
    # Create an SVG image from the QR Code instance
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to string
    svg_string = img.to_string().decode()
    
    return svg_string

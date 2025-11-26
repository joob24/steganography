import streamlit as st
from PIL import Image
import io
import time

PASSWORD = "secret_password"  # You can change this password

def check_password(password_input: str) -> bool:
    return password_input == PASSWORD

SESSION_DURATION = 600  # 10 minutes in seconds

def is_session_valid(key: str) -> bool:
    if key not in st.session_state:
        return False
    last_time = st.session_state[key]
    current_time = time.time()
    return (current_time - last_time) < SESSION_DURATION

def update_session_time(key: str):
    st.session_state[key] = time.time()

def xor_encrypt_decrypt(data: str, key: str) -> str:
    """Simple XOR encryption/decryption"""
    from itertools import cycle
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(key)))

def encode_text_in_image(image: Image.Image, text: str, password: str) -> Image.Image:
    """Encode a text message into an image using LSB steganography with password encryption"""
    encrypted_text = xor_encrypt_decrypt(text, password)
    # Append EOF delimiter to encrypted text
    eof_marker = chr(3)*4  # Using 4x End Of Text char (ETX, ASCII 3) as EOF marker
    encrypted_text += eof_marker

    # Convert encrypted text to binary
    binary_text = ''.join(f'{ord(c):08b}' for c in encrypted_text)

    # Calculate maximum bits capacity in the image
    max_bits = image.width * image.height * 3  # 3 bits per pixel (R, G, B)
    if len(binary_text) > max_bits:
        st.error(f"Pesan terlalu panjang untuk gambar ini. Maksimum karakter pesan: {(max_bits // 8) - 4}")
        raise ValueError("Pesan terlalu panjang untuk gambar.")

    image = image.convert('RGB')
    data = list(image.getdata())

    new_data = []
    digit_index = 0
    for pixel in data:
        r, g, b = pixel
        if digit_index < len(binary_text):
            r = (r & ~1) | int(binary_text[digit_index])
            digit_index += 1
        if digit_index < len(binary_text):
            g = (g & ~1) | int(binary_text[digit_index])
            digit_index += 1
        if digit_index < len(binary_text):
            b = (b & ~1) | int(binary_text[digit_index])
            digit_index += 1
        new_data.append((r, g, b))
    # Fill the rest of pixels if any remain unchanged
    while len(new_data) < len(data):
        new_data.append(data[len(new_data)])
    encoded_img = Image.new(image.mode, image.size)
    encoded_img.putdata(new_data)
    return encoded_img

def decode_text_from_image(image: Image.Image, password: str) -> str:
    """Decode a hidden text message from an image using LSB steganography with password decryption"""
    image = image.convert('RGB')
    data = image.getdata()

    binary_data = ''
    for pixel in data:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

    bytes_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_chars = []
    last_index = -1
    for i, byte in enumerate(bytes_list):
        # Looking for EOF marker pattern: 4 consecutive ETX chars (ASCII 3)
        if byte == '00000011':  # ASCII 3 in binary
            # Check next three bytes
            if bytes_list[i:i+4] == ['00000011']*4:
                last_index = i
                break
        decoded_chars.append(chr(int(byte, 2)))
    if last_index != -1:
        # Cut message before EOF
        decoded_chars = decoded_chars[:last_index]
    encrypted_text = ''.join(decoded_chars)
    try:
        decrypted_text = xor_encrypt_decrypt(encrypted_text, password)
    except Exception as e:
        st.error(f"Error during decryption: {e}")
        decrypted_text = ''

    # If decrypted_text contains non-printable characters or empty, alert failure
    if not decrypted_text or any(ord(c) < 32 and c not in '\n\r\t' for c in decrypted_text):
        st.warning("Decoded text contains invalid characters or is empty; possibly wrong password or corrupted data.")
        return ''  # Indicate failure to decode properly with password
    return decrypted_text


def encode_image_to_base64_text(image: Image.Image) -> str:
    """Encode an image to a base64 string"""
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    img_bytes = buffered.getvalue()
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')
    return img_base64

def decode_base64_text_to_image(base64_text: str) -> Image.Image:
    """Decode a base64 string to an image"""
    try:
        img_bytes = base64.b64decode(base64_text)
        image = Image.open(io.BytesIO(img_bytes))
        return image
    except Exception as e:
        st.error(f"Failed to decode image from text: {e}")
        return None

def main():
    st.set_page_config(page_title="Steganography Encryption App", layout="centered", page_icon="🔐")

    st.title("🔐 Steganography Encryption")
    st.markdown(
        """
        Hide your secret messages inside images using steganography.\n
        Upload an image and the text you want to hide, then download the encoded image.
        Or upload an encoded image to decode hidden message.
        Or convert an image to text or text back to image.
        """
    )

    tab1, tab2 = st.tabs(["Encode", "Decode"])

    with tab1:
        st.header("Encode Secret Message")
        uploaded_image = st.file_uploader("Choose an image to hide your message in", type=["png", "jpg", "jpeg"], key="encode_img")
        secret_text = st.text_area("Enter the secret message to hide", key="encode_text")
        password = st.text_input("Enter password for encoding:", type="password", key="encode_pw_process")

        encode_clicked = st.button("Process Encode")
        if encode_clicked:
            if password is None or password.strip() == "":
                st.error("Please enter the password for encoding.")
            elif uploaded_image is None:
                st.error("Please upload an image to encode.")
            elif not secret_text:
                st.error("Please enter a secret message to encode.")
            else:
                try:
                    image = Image.open(uploaded_image)
                    encoded_image = encode_text_in_image(image, secret_text, password)
                    st.image(encoded_image, caption="Encoded Image Preview", use_column_width=True)

                    # Save encoded image to bytes and reload for decoding test
                    buf = io.BytesIO()
                    encoded_image.save(buf, format="PNG")
                    buf.seek(0)
                    reloaded_image = Image.open(buf)

                    # Decode immediately for verification from reloaded image
                    decoded_text = decode_text_from_image(reloaded_image, password)
                    st.text_area("Decoded Message (for verification)", value=decoded_text, height=150)

                    buf = io.BytesIO()
                    encoded_image.save(buf, format="PNG")
                    byte_im = buf.getvalue()

                    st.download_button(
                        label="Download Encoded Image",
                        data=byte_im,
                        file_name="encoded_image.png",
                        mime="image/png"
                    )
                except Exception as e:
                    st.error(f"An error occurred: {e}")

    with tab2:
        st.header("Decode Secret Message")
        encoded_image_file = st.file_uploader("Upload an encoded image to decode", type=["png", "jpg", "jpeg"], key="decode_img")
        password = st.text_input("Enter password for decoding:", type="password", key="decode_password")

        decode_clicked = st.button("Process Decode")
        if decode_clicked:
            if password is None or password.strip() == "":
                st.error("Please enter the password for decoding.")
            elif encoded_image_file is None:
                st.error("Please upload an encoded image to decode.")
            else:
                try:
                    image = Image.open(encoded_image_file)
                    decoded_text = decode_text_from_image(image, password)
                    if decoded_text:
                        st.text_area("Decoded Secret Message", value=decoded_text, height=150)
                    else:
                        st.warning("No hidden message found or incorrect password.")
                except Exception as e:
                    st.error(f"An error occurred: {e}")

    st.markdown("---")
    st.markdown(
        """
        joe wevil - developtment python streamlit\n
        Note: Image must be large enough to hold your message. Each character requires 8 bits, each pixel can encode 3 bits.
        """
    )

if __name__ == "__main__":
    main()


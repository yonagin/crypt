import os
import argparse
from cryptography.fernet import Fernet
import base64
import hashlib
from tqdm import tqdm


def generate_key(password):
    """从密码生成加密密钥"""
    password = password.encode()
    key = hashlib.sha256(password).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_folder(input_folder, output_folder, password):
    """加密文件夹中的所有文件"""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    key = generate_key(password)
    fernet = Fernet(key)

    # 递归处理所有文件
    for root, _, files in os.walk(input_folder):
        # 创建对应的输出目录结构
        rel_path = os.path.relpath(root, input_folder)
        out_dir = os.path.join(output_folder, rel_path)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        print(f"正在加密目录 {rel_path} 中的文件...")
        for file_name in tqdm(files):
            input_path = os.path.join(root, file_name)
            output_path = os.path.join(out_dir, file_name + ".enc")

            with open(input_path, 'rb') as file:
                data = file.read()

            encrypted_data = fernet.encrypt(data)

            with open(output_path, 'wb') as file:
                file.write(encrypted_data)

    # 保存密钥验证文件（用于测试解密是否成功）
    test_file_path = os.path.join(output_folder, ".key_test")
    with open(test_file_path, 'wb') as f:
        f.write(fernet.encrypt(b"Encryption key test file"))

    print(f"加密完成! 加密后的文件保存在: {output_folder}")
    print(f"请记住你的密码: {password}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='加密数据集文件夹')
    parser.add_argument('--input', help='输入文件夹路径')
    parser.add_argument('--output', help='输出文件夹路径')
    parser.add_argument('--key', default=None, help='加密密码(如不提供将自动生成)')

    args = parser.parse_args()

    encrypt_folder(args.input, args.output, args.key)

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


def verify_password(encrypted_folder, password):
    """验证密码是否正确"""
    key = generate_key(password)
    fernet = Fernet(key)

    test_file_path = os.path.join(encrypted_folder, ".key_test")
    if not os.path.exists(test_file_path):
        print("警告: 未找到密钥测试文件，无法验证密码是否正确")
        return True

    try:
        with open(test_file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        if decrypted_data == b"Encryption key test file":
            return True
        return False
    except Exception:
        return False


def decrypt_folder(input_folder, output_folder, password):
    """解密文件夹中的所有文件"""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # 验证密码
    if not verify_password(input_folder, password):
        print("错误: 密码不正确，无法解密文件")
        return

    key = generate_key(password)
    fernet = Fernet(key)

    # 递归处理所有加密文件
    for root, _, files in os.walk(input_folder):
        # 创建对应的输出目录结构
        rel_path = os.path.relpath(root, input_folder)
        out_dir = os.path.join(output_folder, rel_path)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # 筛选出加密文件
        encrypted_files = [f for f in files if f.endswith('.enc') and f != ".key_test"]

        if encrypted_files:
            print(f"正在解密目录 {rel_path} 中的 {len(encrypted_files)} 个文件...")
            for file_name in tqdm(encrypted_files):
                input_path = os.path.join(root, file_name)
                output_path = os.path.join(out_dir, file_name[:-4])  # 去掉 .enc 后缀

                with open(input_path, 'rb') as file:
                    encrypted_data = file.read()

                try:
                    decrypted_data = fernet.decrypt(encrypted_data)

                    with open(output_path, 'wb') as file:
                        file.write(decrypted_data)
                except Exception as e:
                    print(f"解密文件 {file_name} 失败: {str(e)}")

    print(f"解密完成! 解密后的文件保存在: {output_folder}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='解密数据集文件夹')
    parser.add_argument('--input', help='加密文件夹路径')
    parser.add_argument('--output', help='解密输出文件夹路径')
    parser.add_argument('--key', help='解密密码')

    args = parser.parse_args()
    decrypt_folder(args.input, args.output, args.key)

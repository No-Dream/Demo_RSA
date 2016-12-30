using System;
using System.IO;
using System.Security.Cryptography;

namespace Demo_RSA
{
    class CreateRSA
    {
        protected RSACryptoServiceProvider m_RSA;

        string m_PublicKey;
        string m_PrivateKey;

        public string PublicKey
        {
            get { return m_PublicKey; }
        }
        public string PrivateKey
        {
            get { return m_PrivateKey; }
        }

        public CreateRSA()
        {
            m_RSA = new RSACryptoServiceProvider();

            //Get Key
            m_PublicKey = m_RSA.ToXmlString(false);
            m_PrivateKey = m_RSA.ToXmlString(true);
        }

    }

    static class RSA_API
    {
        public static byte[] API_EnFile(byte[] p_FileBytes, string p_PublicKey, bool p_Padding)
        {
            try
            {
                RSACryptoServiceProvider t_RSA = new RSACryptoServiceProvider();
                t_RSA.FromXmlString(p_PublicKey);

                //分段加密
                int t_KeySize = t_RSA.KeySize / 8;
                int t_BufferSize = t_KeySize - 11;

                byte[] t_Buffer = new byte[t_BufferSize];
                MemoryStream t_MS_In = new MemoryStream(p_FileBytes);
                MemoryStream t_MS_Out = new MemoryStream();

                while (true)
                {
                    int t_ReadLength = t_MS_In.Read(t_Buffer, 0, t_BufferSize);
                    if (t_ReadLength <= 0)
                    {
                        break;
                    }

                    byte[] t_ReadBytes = new byte[t_ReadLength];
                    Array.Copy(t_Buffer, 0, t_ReadBytes, 0, t_ReadLength);

                    byte[] t_SecBytes = t_RSA.Encrypt(t_ReadBytes, p_Padding);
                    t_MS_Out.Write(t_SecBytes, 0, t_SecBytes.Length);
                }

                return t_MS_Out.ToArray();
            }
            catch (CryptographicException e)
            {
                return null;
            }
        }

        public static byte[] API_DeFile(byte[] p_FileBytes, string p_PrivateKey, bool p_Padding)
        {
            try
            {
                RSACryptoServiceProvider t_RSA = new RSACryptoServiceProvider();
                t_RSA.FromXmlString(p_PrivateKey);

                //分段解密
                int t_KeySize = 128;

                byte[] t_Buffer = new byte[t_KeySize];
                MemoryStream t_MS_In = new MemoryStream(p_FileBytes);
                MemoryStream t_MS_Out = new MemoryStream();

                while (true)
                {
                    int t_ReadLine = t_MS_In.Read(t_Buffer, 0, t_KeySize);
                    if (t_ReadLine <= 0)
                    {
                        break;
                    }

                    byte[] t_ReadBytes = new byte[t_ReadLine];
                    Array.Copy(t_Buffer, 0, t_ReadBytes, 0, t_ReadLine);

                    byte[] t_UnSecBytes = t_RSA.Decrypt(t_ReadBytes, p_Padding);
                    t_MS_Out.Write(t_UnSecBytes, 0, t_UnSecBytes.Length);
                }

                return t_MS_Out.ToArray();
            }
            catch (CryptographicException e)
            {
                return null;
            }
        }

        public static byte[] API_RSASign(byte[] p_RawDataBytes, string p_PrivateKey)
        {
            try
            {
                RSACryptoServiceProvider t_RSA = new RSACryptoServiceProvider();
                t_RSA.FromXmlString(p_PrivateKey);

                byte[] t_SignedData = t_RSA.SignData(p_RawDataBytes, new SHA1CryptoServiceProvider());
                return t_SignedData;
            }
            catch (CryptographicException e)
            {
                return null;
            }
        }

        public static bool API_RSACheckSign(byte[] p_RawDataBytes, byte[] p_SignedDataBytes, string m_PublicKey)
        {
            try
            {
                RSACryptoServiceProvider t_RSA = new RSACryptoServiceProvider();
                t_RSA.FromXmlString(m_PublicKey);

                return t_RSA.VerifyData(p_RawDataBytes, new SHA1CryptoServiceProvider(), p_SignedDataBytes);

            }
            catch (CryptographicException e)
            {
                return false;
            }
        }


    }
}

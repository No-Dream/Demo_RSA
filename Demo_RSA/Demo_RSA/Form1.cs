using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Demo_RSA
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        CreateRSA m_RSA;
        private void Form1_Load(object sender, EventArgs e)
        {
            m_RSA = new CreateRSA();
        }

        private byte[] ReadFile(string p_Path)
        {
            if (!File.Exists(p_Path))
            {
                return null;
            }

            try
            {
                FileStream t_FS = File.OpenRead(p_Path);
                BinaryReader t_Reader = new BinaryReader(t_FS);
                byte[] t_RawBytes = new byte[t_FS.Length];
                t_Reader.Read(t_RawBytes, 0, Convert.ToInt32(t_FS.Length));
                t_Reader.Close();
                t_FS.Close();

                return t_RawBytes;
            }
            catch (Exception e)
            {
                return null;
            }

        }

        private bool WriteFile(string p_Path, byte[] p_FileBytes)
        {
            if (File.Exists(p_Path))
            {
                File.Delete(p_Path);
            }

            try
            {
                FileStream t_FS = File.OpenWrite(p_Path);
                BinaryWriter t_Writer = new BinaryWriter(t_FS);
                t_Writer.Write(p_FileBytes);
                t_Writer.Close();
                t_FS.Close();

                return true;
            }
            catch (Exception e)
            {
                return false;
            }

        }

        private void EnFile_Click(object sender, EventArgs e)
        {
            string t_ReadPath = textBox1.Text;
            string t_SavePath = textBox2.Text;

            byte[] t_RawBytes = ReadFile(t_ReadPath);
            byte[] t_SecBytes = RSA_API.API_EnFile(t_RawBytes, m_RSA.PublicKey, false);
            bool t_Res = WriteFile(t_SavePath, t_SecBytes);
        }

        private void DeFile_Click(object sender, EventArgs e)
        {
            string t_ReadPath = textBox1.Text;
            string t_SavePath = textBox2.Text;

            byte[] t_SecBytes = ReadFile(t_ReadPath);
            byte[] t_RawBytes = RSA_API.API_DeFile(t_SecBytes, m_RSA.PrivateKey, false);
            bool t_Res = WriteFile(t_SavePath, t_RawBytes);
        }

        private void RSASign_Click(object sender, EventArgs e)
        {
            string t_ReadPath = textBox1.Text;
            string t_SavePath = textBox2.Text;

            byte[] t_RawBytes = ReadFile(t_ReadPath);
            byte[] t_SecBytes = RSA_API.API_RSASign(t_RawBytes, m_RSA.PrivateKey);
            bool t_Res = WriteFile(t_SavePath, t_SecBytes);
        }

        private void CheckSign_Click(object sender, EventArgs e)
        {
            string t_ReadPath = textBox1.Text;
            string t_SavePath = textBox2.Text;

            byte[] t_RawBytes = ReadFile(t_ReadPath);
            byte[] t_SecBytes = ReadFile(t_SavePath);

            bool t_Res = RSA_API.API_RSACheckSign(t_RawBytes, t_SecBytes, m_RSA.PublicKey);

            MessageBox.Show(t_Res.ToString());
        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog open = new OpenFileDialog();
            if (open.ShowDialog() == DialogResult.OK)
            {
                textBox1.Text = open.FileName;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            SaveFileDialog save = new SaveFileDialog();
            if (save.ShowDialog() == DialogResult.OK)
            {
                textBox2.Text = save.FileName;
            }
        }
    }
}

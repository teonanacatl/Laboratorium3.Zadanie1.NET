using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace Laboratorium3.Zadanie1.NET;

public partial class MainWindow : Window
{
    private readonly Stopwatch _stopwatch;
    private SymmetricAlgorithm _algorithm;
    private double _decryptTime;
    private double _encryptTime;

    public MainWindow()
    {
        InitializeComponent();
        algorithmComboBox.Items.Add("AES");
        algorithmComboBox.Items.Add("DES");
        algorithmComboBox.Items.Add("RC2");
        algorithmComboBox.Items.Add("Rijndael");
        algorithmComboBox.Items.Add("TripleDES");
        algorithmComboBox.SelectedIndex = 0;
        _stopwatch = new Stopwatch();
        SetAlgorithm();
    }

    private void SetAlgorithm()
    {
        _algorithm = algorithmComboBox.SelectedItem switch
        {
            "AES" => Aes.Create(),
            "DES" => DES.Create(),
            "RC2" => RC2.Create(),
            "Rijndael" => Rijndael.Create(),
            "TripleDES" => TripleDES.Create(),
            _ => throw new InvalidOperationException("Unsupported algorithm selected")
        };

        keyTextBox.Text = BitConverter.ToString(_algorithm.Key).Replace("-", "");
        ivTextBox.Text = BitConverter.ToString(_algorithm.IV).Replace("-", "");
    }

    private void OnAlgorithmSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SetAlgorithm();
    }

    private void OnGenerateKeyAndIVButtonClick(object sender, RoutedEventArgs e)
    {
        _algorithm.GenerateKey();
        _algorithm.GenerateIV();

        keyTextBox.Text = BitConverter.ToString(_algorithm.Key).Replace("-", "");
        ivTextBox.Text = BitConverter.ToString(_algorithm.IV).Replace("-", "");
    }

    private void OnEncryptButtonClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(plaintextTextBox.Text))
        {
            MessageBox.Show(
                "Please enter plaintext to encrypt.",
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
            return;
        }

        _stopwatch.Restart();
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintextTextBox.Text);
        var ciphertextBytes = EncryptStringToBytes(
            plaintextBytes,
            _algorithm.Key,
            _algorithm.IV,
            _algorithm
        );
        _stopwatch.Stop();
        _encryptTime = _stopwatch.Elapsed.TotalMilliseconds;

        ciphertextTextBox.Text = Convert.ToBase64String(ciphertextBytes);
        ciphertextHexTextBox.Text = BitConverter.ToString(ciphertextBytes).Replace("-", "");
    }

    private void OnDecryptButtonClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ciphertextHexTextBox.Text))
        {
            MessageBox.Show(
                "Please enter ciphertext to decrypt.",
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
            return;
        }

        _stopwatch.Restart();
        var ciphertextBytes = StringToByteArray(ciphertextHexTextBox.Text);
        var plaintextBytes = DecryptStringFromBytes(
            ciphertextBytes,
            _algorithm.Key,
            _algorithm.IV,
            _algorithm
        );
        _stopwatch.Stop();
        _decryptTime = _stopwatch.Elapsed.TotalMilliseconds;

        plaintextTextBox.Text = Encoding.UTF8.GetString(plaintextBytes);
        plaintextHexTextBox.Text = BitConverter.ToString(plaintextBytes).Replace("-", "");
    }

    private static byte[] EncryptStringToBytes(
        byte[] plainTextBytes,
        byte[] Key,
        byte[] IV,
        SymmetricAlgorithm algorithm
    )
    {
        if (plainTextBytes == null || plainTextBytes.Length <= 0)
            throw new ArgumentNullException(nameof(plainTextBytes));
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException(nameof(Key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        using var encryptor = algorithm.CreateEncryptor(Key, IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        {
            csEncrypt.Write(plainTextBytes, 0, plainTextBytes.Length);
            csEncrypt.FlushFinalBlock();
        }

        return msEncrypt.ToArray();
    }

    private static byte[] DecryptStringFromBytes(
        byte[] cipherTextBytes,
        byte[] Key,
        byte[] IV,
        SymmetricAlgorithm algorithm
    )
    {
        if (cipherTextBytes == null || cipherTextBytes.Length <= 0)
            throw new ArgumentNullException(nameof(cipherTextBytes));
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException(nameof(Key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        using var decryptor = algorithm.CreateDecryptor(Key, IV);
        using var msDecrypt = new MemoryStream(cipherTextBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var msPlainText = new MemoryStream();
        csDecrypt.CopyTo(msPlainText);
        return msPlainText.ToArray();
    }

    private static byte[] StringToByteArray(string hex)
    {
        var numberChars = hex.Length;
        var bytes = new byte[numberChars / 2];
        for (var i = 0; i < numberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return bytes;
    }

    private void OnGetEncryptTimeButtonClick(object sender, RoutedEventArgs e)
    {
        encryptTimeTextBox.Text = _encryptTime + " ms";
    }

    private void OnGetDecryptTimeButtonClick(object sender, RoutedEventArgs e)
    {
        decryptTimeTextBox.Text = _decryptTime + " ms";
    }
}

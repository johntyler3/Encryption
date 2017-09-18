package john.cipher;

import android.content.Context;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Decryption extends AppCompatActivity {

    //TODO: create the add key button in the decryption activity

    // These S-box tables are modified from GO's website:  https://golang.org/src/crypto/aes/const.go#L80
    private static final int[][] SBOX = new int[][]{
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    private static final int[][] SBOX_INVERSE = new int[][]{
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    //got this from https://en.wikipedia.org/wiki/Rijndael_key_schedule
    private static final int[] rcon = new int[]{
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };

    final static int[] LogTable = {
            0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3,
            100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193,
            125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120,
            101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142,
            150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56,
            102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16,
            126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186,
            43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87,
            175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,
            44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160,
            127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183,
            204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157,
            151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,
            83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171,
            68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165,
            103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};

    final static int[] AlogTable = {
            1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
            95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
            229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
            83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
            76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
            131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
            181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
            254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
            251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
            195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
            159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
            155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
            252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
            69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
            18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
            57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_decryption);

        Intent intent = getIntent();
        String message = intent.getStringExtra(MainActivity.THIS_MESSAGE);
        String key = intent.getStringExtra(MainActivity.KEY_TEXT);

        TextView textView = (TextView) findViewById(R.id.yourKey);
        textView.setText(key);
        generate(message, key);
    }

    protected void generate(String message, String decrypt_key) {
        byte[][] key;
        key = generateKey(decrypt_key);
        decrypt(key, message);
    }

    //generateKey takes the hex key you are given and turns it into a 2D byte array
    private static byte[][] generateKey(String keyString)
    {
        byte[][] key = new byte[4][8];

        int index = 0;
        for(int i = 0; i < 8; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                String intString = keyString.substring(index, index + 2);

                key[j][i] = (byte)(Integer.parseInt(intString.toUpperCase(), 16));
                index += 2;
            }
        }

        return key;
    }

    private static byte[][] stringToByte(String in)
    {
        for (int i = in.length(); i < 32; ++i)
        {
            in += "0";
        }

        int index = 0;
        byte[][] out = new byte[4][4];
        for(int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                out[j][i] = (byte)(Integer.parseInt(in.substring(index,index +2).toUpperCase(), 16));
                index += 2;
            }
        }
        return out;
    }

    private static byte[][] subBytesInv(byte[][] before)
    {
        for ( int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                int lower = before[i][j] & 0x0F;
                int higher = (before[i][j] & 0xF0) >> 4;

                before[i][j] = (byte)(SBOX_INVERSE[higher][lower] & 0xFF);
            }
        }

        return before;
    }

    private static byte[][] shiftRowRight(byte[][] before)
    {
        int diff = 1;
        for (int i = 1; i < 4; ++i)
        {
            byte[] copy = before[i].clone();
            for (int j = 0; j < 4; ++j)
            {
                int newIndex = j - diff;
                if (newIndex < 0)
                    newIndex += 4;
                before[i][j] = copy[newIndex];
            }
            diff++;
        }
        return before;
    }

    ////////////////////////  the mixColumns Tranformation ////////////////////////

    private static byte mul (int a, byte b) {
        int inda = (a < 0) ? (a + 256) : a;
        int indb = (b < 0) ? (b + 256) : b;

        if ( (a != 0) && (b != 0) ) {
            int index = (LogTable[inda] + LogTable[indb]);
            byte val = (byte)(AlogTable[ index % 255 ] );
            return val;
        }
        else
            return 0;
    } // mul


    public static byte [][] invMixColumn2 (int c, byte[][] st) {
        byte a[] = new byte[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = st[i][c];

        st[0][c] = (byte)(mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]));
        st[1][c] = (byte)(mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]));
        st[2][c] = (byte)(mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]));
        st[3][c] = (byte)(mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]));

        return st;
    }

    private static byte[] expandKey(byte[][] key) {
        byte[] tempKey = new byte[4];
        byte[] previous = new byte[4];
        byte[] expandedKey = new byte[256];
        int index = 0;
        int iteration = 1;

        int tempIndex = 0;

        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {

                byte temp = key[j][i];
                expandedKey[index] = temp;
                index++;
            }
        }

        while (index < 240) {
            tempIndex = 0;
            for (int a = index - 4; a < index; a++) {
                tempKey[tempIndex] = expandedKey[a];
                previous[tempIndex] = expandedKey[a];
                tempIndex++;
            }

            //perform rotation with iteration value
            tempKey = scheduleCore(iteration, tempKey);
            for (int i = 0; i < 4; i++) {
                expandedKey[index] = (byte)(tempKey[i] ^ expandedKey[index - 32]);
                index++;
            }

            for(int i = 0; i < 12; i++) {
                expandedKey[index] = (byte)(expandedKey[index - 4] ^ expandedKey[index - 32]);
                index++;
            }

            for(int i = 0; i < 4; i++) {
                int lower = expandedKey[index - 4] & 0x0F;
                int higher = (expandedKey[index - 4] & 0xF0) >> 4;

                expandedKey[index] = (byte)((SBOX[higher][lower] & 0xFF) ^ expandedKey[index - 32]);
                index++;
            }

            for(int i = 0; i < 12; i++) {
                expandedKey[index] = (byte)(expandedKey[index - 4] ^ expandedKey[index - 32]);
                index++;
            }

            iteration++;
        }

        return Arrays.copyOfRange(expandedKey, 0, 240);
    }

    private static byte[] scheduleCore(int iteration, byte[] temp) {
        //rotate
        byte[] copy = temp.clone();
        for (int j = 0; j < 4; ++j)
        {
            int newIndex = j + 1;
            if (newIndex >= 4)
                newIndex -= 4;
            temp[j] = copy[newIndex];
        }

        //do SBOX
        for (int j = 0; j < 4; j++)
        {
            int lower = temp[j] & 0x0F;
            int higher = (temp[j] & 0xF0) >> 4;

            temp[j] = (byte)(SBOX[higher][lower] & 0xFF);
        }

        temp[0] ^= rcon[iteration];

        return temp;
    }

    //getState is called by both the encryption and decryption methods to print the results
    private String getState(byte[][] b)
    {
        StringBuilder s = new StringBuilder();
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                s.append(String.format("%02X",b[k][j]));
            }
        }
        String hexString = s.toString();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < hexString.length(); i += 2) {
            String str = hexString.substring(i, i + 2);
            sb.append((char)Integer.parseInt(str, 16));
        }

        return sb.toString();
    }

    private static byte[][] addRoundKey(byte[] expandedKey, int index, byte[][] ciphertext)
    {
        byte[] key = Arrays.copyOfRange(expandedKey, index, index + 16);
        int in = 0;
        for (int i = 0; i < 4; ++i){
            for (int j = 0; j < 4; ++j){
                ciphertext[j][i] ^= key[in];
                in++;
            }
        }
        return ciphertext;
    }

    //decrypt takes in a 2D byte array that represents the key and a string with the
    //encrypted Hex generated by encrypt()
    private void decrypt(byte[][] key, String encryptedHex)
    {
        String line = "";
        byte[][] bytes = new byte[4][4];
        byte[] result = new byte[240];
        int roundNumber = 0;

        StringBuilder sb = new StringBuilder();

        result = expandKey(key);
        Scanner sc = new Scanner (encryptedHex);

        while (sc.hasNext()) {
            line = sc.next();

            roundNumber = 224;
            try{
                bytes = stringToByte(line);
            }
            catch (NumberFormatException e){
                // If input isn't in hex just skip the line
                continue;
            }

            bytes = addRoundKey(result, roundNumber, bytes);
            bytes = shiftRowRight(bytes);
            bytes = subBytesInv(bytes);

            roundNumber -= 16;

            for (int round = 0; round < 13; round++)
            {
                bytes = addRoundKey(result, roundNumber, bytes);
                roundNumber -= 16;


                for (int i = 0; i < 4; i++)
                {
                    bytes = invMixColumn2(i,bytes);
                }

                bytes = shiftRowRight(bytes);
                bytes = subBytesInv(bytes);

            }
            bytes = addRoundKey(result, roundNumber, bytes);
            Log.d("JTtag", "setting the string builder sb");
            sb.append(getState(bytes) + " ");
            Log.d("JTtag", "sb is now : " + sb.toString());
        }
        TextView textView = (TextView) findViewById(R.id.decryptedText);
        Log.d("JTtag", "setting textview to : " + sb.toString());
        textView.setText(sb.toString());
    }
}





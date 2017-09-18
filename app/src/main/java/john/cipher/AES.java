package john.cipher;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class AES extends AppCompatActivity {

    public String thisKey;

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
        setContentView(R.layout.activity_aes);

        Intent intent = getIntent();
        String message = intent.getStringExtra(MainActivity.THIS_MESSAGE);
        getKey();
        generate(message);
    }

    public void addKey(MenuItem item) {

        //TOAST for adding a key
        Context context = getApplicationContext();
        CharSequence text = "Key Saved to My Keys";
        int duration = Toast.LENGTH_SHORT;
        Toast toast = Toast.makeText(context, text, duration);
        toast.setGravity(Gravity.CENTER,0,0);

        //adding the key via shared preferences
        SharedPreferences listKeys = getSharedPreferences("myKeys", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = listKeys.edit();
        editor.putString(thisKey, thisKey);
        Log.d("JTtag", "adding key " + thisKey + " to the shared preferences");
        editor.apply();
        toast.show();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_add_key, menu);
        return true;
    }

    protected void generate(String message) {
        byte[][] key;
        TextView textview = (TextView) findViewById(R.id.key);
        textview.setText(thisKey);
        key = generateKey(thisKey);
        encrypt(key, message);
    }

    private void getKey() {
        int length = 64;
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length) {
            sb.append(Integer.toHexString(random.nextInt()));
        }
        thisKey = sb.toString();
    }

    //generateKey
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

    private static String stringToHex(String in) {
        StringBuilder sb = new StringBuilder();
        for (char ch : in.toCharArray()) {
            sb.append(Integer.toHexString((int)ch).toUpperCase());
        }
        return sb.toString();
    }

    private static byte[][] subBytes(byte[][] before)
    {
        for ( int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                int lower = before[i][j] & 0x0F;
                int higher = (before[i][j] & 0xF0) >> 4;

                before[i][j] = (byte)(SBOX[higher][lower] & 0xFF);
            }
        }

        return before;
    }

    private static byte[][] shiftRowLeft(byte[][] before)
    {
        int diff = 1;
        for (int i = 1; i < 4; ++i)
        {
            byte[] copy = before[i].clone();
            for (int j = 0; j < 4; ++j)
            {
                int newIndex = j + diff;
                if (newIndex >= 4)
                    newIndex -= 4;
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

    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments.

    public static byte[][] mixColumn2 (int c, byte[][] st) {
        // This is another alternate version of mixColumn, using the
        // logtables to do the computation.

        byte a[] = new byte[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = st[i][c];

        // This is exactly the same as mixColumns1, if
        // the mul columns somehow match the b columns there.
        st[0][c] = (byte)(mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
        st[1][c] = (byte)(mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
        st[2][c] = (byte)(mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
        st[3][c] = (byte)(mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));

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

    private void encrypt(byte[][] key, String message)
    {
        String line = "";
        byte[][] bytes = new byte[4][4];
        byte[] result = new byte[240];
        int roundNumber = 0;
        StringBuilder sb = new StringBuilder();

        Scanner sc = new Scanner(message);
        result = expandKey(key);

        while(sc.hasNext()) {

            line = stringToHex(sc.next());
            Log.d("JTtag", "line = sc.next is " + line);

            roundNumber = 0;
                try {
                    bytes = stringToByte(line);
                } catch (NumberFormatException e) {
                    // If input isn't in hex just skip the line
                    continue;
                }

                bytes = addRoundKey(result, roundNumber, bytes);
                roundNumber += 16;
                for (int round = 0; round < 13; round++) {
                    bytes = subBytes(bytes);
                    bytes = shiftRowLeft(bytes);

                    for (int i = 0; i < 4; i++)
                        bytes = mixColumn2(i, bytes);

                    bytes = addRoundKey(result, roundNumber, bytes);
                    roundNumber += 16;
                }

                // Last round doesn't have mixColumns
                bytes = subBytes(bytes);
                bytes = shiftRowLeft(bytes);
                bytes = addRoundKey(result, roundNumber, bytes);

                Log.d("JTtag", "appending to the StringBuilder sb");
                sb.append(getState(bytes));
                sb.append("\n");
                Log.d("JTtag", "sb is now : " + sb.toString());
            }
        Log.d("JTtag", "trying to set textview");
        TextView textView = (TextView) findViewById(R.id.encryptedText);
        textView.setText(sb.toString());
    }

    //getState is called by both the encryption and decryption methods to print the results
    private String getState(byte[][] b)
    {
        StringBuilder s = new StringBuilder("");
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                s.append(String.format("%02X",b[k][j]));
            }
        }
        return s.toString();
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
}





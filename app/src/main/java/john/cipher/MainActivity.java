package john.cipher;

import android.app.FragmentManager;
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
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

//TODO: create the add key button in the main activity
//TODO: make the app only in portrait mode

public class MainActivity extends AppCompatActivity {

    public static final String THIS_MESSAGE = "THIS MESSAGE";
    public static final String KEY_TEXT = "KEY_TEXT";
    //public boolean ENCODE_BOOL = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.about:
                startActivity(new Intent(this, About.class));
                return true;
//            case R.id.aes:
//                startActivity(new Intent(this, AboutAES.class));
//                return true;
            case R.id.keys:
                startActivity(new Intent(this, Saved_Keys.class));
                return true;
            case R.id.add_key:
                EditText keyText = (EditText) findViewById(R.id.keyText);
                String key = keyText.getText().toString();

                //TOAST for adding a key
                Context context = getApplicationContext();
                CharSequence text = "Key Saved to My Keys";
                int duration = Toast.LENGTH_SHORT;

                if (key.length() < 64 || key.length() >= 72)
                    text = "Include a Valid Encryption Key";
                else {
                    //adding the key via shared preferences
                    SharedPreferences listKeys = getSharedPreferences("myKeys", Context.MODE_PRIVATE);
                    SharedPreferences.Editor editor = listKeys.edit();

                    editor.putString(key, key);
                    Log.d("JTtag", "adding key " + key + " to the shared preferences");

                    editor.apply();
                }

                Toast toast = Toast.makeText(context, text, duration);
                toast.setGravity(Gravity.CENTER, 0, 0);
                toast.show();

                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    public void encrypt(View view) {
        Intent intent = new Intent (this, AES.class);
        EditText editText = (EditText) findViewById(R.id.editText);
        String message = editText.getText().toString();
        intent.putExtra(THIS_MESSAGE, message);
        startActivity(intent);
    }

    public void decode(View view) {
        Intent intent = new Intent (this, Decryption.class);
        EditText editText = (EditText) findViewById(R.id.editText);
        EditText keyText = (EditText) findViewById(R.id.keyText);
        String message = editText.getText().toString();
        String key = keyText.getText().toString();

        //decrypt without a key TOAST
        Context context = getApplicationContext();
        CharSequence text = "Please Enter a Valid Key for Decryption!";
        int duration = Toast.LENGTH_SHORT;
        Toast toast = Toast.makeText(context, text, duration);
        toast.setGravity(Gravity.CENTER,0,0);

        intent.putExtra(THIS_MESSAGE, message);
        intent.putExtra(KEY_TEXT, key);

        //TODO: check everycharacter and make sure it is a hexidecimal character before calling decryption
        if (key.length() < 64 || key.length() >= 72)
            toast.show();
        else
            startActivity(intent);
    }
}

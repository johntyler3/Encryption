package john.cipher;

import android.app.FragmentManager;
import android.app.ListActivity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

/**
 * Created by jtthomas on 9/6/17.
 */

public class Saved_Keys extends ListActivity {

    //List of array strings serving as list of items
    ArrayList<String> listKeys = new ArrayList<>();

    //defining a string adapter which will handle the data of the list view
    ArrayAdapter<String> adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_saved_keys);
        ListView listView = (ListView) findViewById(android.R.id.list);
        registerForContextMenu(listView);

        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, listKeys);
        setListAdapter(adapter);

        addKeys();

        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView<?> parent, View view,int position, long id) {
                String key = parent.getAdapter().getItem(position).toString();
                copy(key);
                // When clicked, show a toast with the TextView text
                Toast.makeText(getApplicationContext(), "Copied Key : " +
                        ((TextView) view).getText(), Toast.LENGTH_SHORT).show();
            }
        });
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v,
                                    ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_contex, menu);
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        switch (item.getItemId()) {
//            case R.id.nickName:
//                nickNameKey(info.id);
//                return true;
            case R.id.delete:
                deleteKey(info.id);
                return true;
            default:
                return super.onContextItemSelected(item);
        }
    }

    public void copy(String text) {
        try {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            android.content.ClipData clip = android.content.ClipData.newPlainText("WordKeeper", text);
            clipboard.setPrimaryClip(clip);
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), "Error copying key to clipboard", Toast.LENGTH_SHORT).show();
        }
    }

    public void addKeys() {
        SharedPreferences settings = getSharedPreferences("myKeys", Context.MODE_PRIVATE);

        String temp;
        Map<String, String> keys = (Map<String, String>) settings.getAll();
        for(Map.Entry<String, String> entry : keys.entrySet()) {
            temp = entry.getValue();
            Log.d("JTtag", "Adding Value : " + temp + " to listKeys");
            listKeys.add(temp);
        }
        adapter.notifyDataSetChanged();
    }

    public void deleteKey(long itemID) {
        SharedPreferences myKeys = getSharedPreferences("myKeys", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = myKeys.edit();

//        Log.d("JTtag", "Currently these keys are in the shared preferences");
//        Map<String, String> keys = (Map<String, String>) myKeys.getAll();
//        for(Map.Entry<String, String> entry : keys.entrySet()) {
//            Log.d("JTtag", "Key : " + entry.getKey() + " Value " + entry.getValue());
//        }


        //get the listView object
        ListView listView = (ListView) findViewById(android.R.id.list);
        Object o = listView.getItemAtPosition((int)itemID);

        //remove the object from the shared preferences
        editor.remove(o.toString());

//        Log.d("JTtag", "Removing : " + o.toString());

        editor.commit();

        //remove the item from the list
        listKeys.remove((int)itemID);
        adapter.notifyDataSetChanged();


//        Log.d("JTtag", "Currently these keys are in the shared preferences after removal");
//        Map<String, String> Keys = (Map<String, String>) myKeys.getAll();
//        for(Map.Entry<String, String> entry : Keys.entrySet()) {
//            Log.d("JTtag", "Key : " + entry.getKey() + " Value " + entry.getValue());
//        }
    }

    public void nickNameKey(long itemID) {
        SharedPreferences myKeys = getSharedPreferences("myKeys", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = myKeys.edit();

        ListView listView = (ListView) findViewById(android.R.id.list);
        Object o = listView.getItemAtPosition((int)itemID);
    }
}

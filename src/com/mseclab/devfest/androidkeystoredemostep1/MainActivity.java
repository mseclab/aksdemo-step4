package com.mseclab.devfest.androidkeystoredemostep1;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

import android.app.Activity;
import android.app.ActionBar;
import android.app.Fragment;
import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.os.Build;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.mseclab.devfest.androidkeystoredemostep4.R;

public class MainActivity extends Activity {

	private final static String ALIAS = "DEVKEY1";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		if (savedInstanceState == null) {
			getFragmentManager().beginTransaction().add(R.id.container, new PlaceholderFragment()).commit();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		switch (item.getItemId()) {
		case R.id.action_settings:
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	/**
	 * A placeholder fragment containing a simple view.
	 */
	public static class PlaceholderFragment extends Fragment implements View.OnClickListener {

		private Button mGenChiaviButton;
		private Button mFirmaButton;
		private Button mVerificaButton;
		private TextView mDebugText;
		private EditText mInData;
		private EditText mOutData;

		ProgressDialog progressdialog;

		private static final String SIGN_ALG = "SHA256withRSA";
		private static final String TAG = "AndroidKeyStoreDemo";

		public PlaceholderFragment() {
		}

		@Override
		public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
			View rootView = inflater.inflate(R.layout.fragment_main, container, false);

			// Bottoni
			mGenChiaviButton = (Button) rootView.findViewById(R.id.generate_button);
			mGenChiaviButton.setOnClickListener(this);
			mFirmaButton = (Button) rootView.findViewById(R.id.firma_button);
			mFirmaButton.setOnClickListener(this);
			mVerificaButton = (Button) rootView.findViewById(R.id.verifica_button);
			mVerificaButton.setOnClickListener(this);

			// Text View
			mInData = (EditText) rootView.findViewById(R.id.inDataText);
			mOutData = (EditText) rootView.findViewById(R.id.outDataText);
			mDebugText = (TextView) rootView.findViewById(R.id.debugText);

			return rootView;
		}

		@Override
		public void onClick(View view) {

			switch (view.getId()) {
			case R.id.generate_button:
				debug("Cliccato Genera chiavi");
				generaChiavi();
				break;
			case R.id.firma_button:
				debug("Cliccato Firma");
				firmaData();
				break;
			case R.id.verifica_button:
				debug("Cliccato Verifica");
				verificaData();
				break;

			}
		}

		private void generaChiavi() {
			new AsyncTask<Void, String, Void>() {

				@Override
				protected Void doInBackground(Void... params) {
					// TODO Auto-generated method stub
					Context cx = getActivity();
					// Generate a key pair inside the AndroidKeyStore
					Calendar notBefore = Calendar.getInstance();
					Calendar notAfter = Calendar.getInstance();
					notAfter.add(1, Calendar.YEAR);

					android.security.KeyPairGeneratorSpec.Builder builder = new KeyPairGeneratorSpec.Builder(cx);
					builder.setAlias(ALIAS);
					String infocert = String.format("CN=%s, OU=%s", ALIAS, cx.getPackageName());
					builder.setSubject(new X500Principal(infocert));
					builder.setSerialNumber(BigInteger.ONE);
					builder.setStartDate(notBefore.getTime());
					builder.setEndDate(notAfter.getTime());
					KeyPairGeneratorSpec spec = builder.build();

					KeyPairGenerator kpGenerator;
					KeyPair kp = null;
					try {
						kpGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
						kpGenerator.initialize(spec);
						kp = kpGenerator.generateKeyPair();

						publishProgress("Generated key pair : " + kp.toString());
						PublicKey publickey = kp.getPublic();
						PrivateKey privateKey = kp.getPrivate();
						publishProgress("Formato della chiave pubblica : " + publickey.getFormat());
						publishProgress("Algoritmo utilizzato : " + publickey.getAlgorithm());
						if (privateKey.getEncoded() == null)
							publishProgress("Non possibile accedere direttamente alla chiave privata :-(");

					} catch (NoSuchAlgorithmException e) {
						debug(e.toString());
					} catch (NoSuchProviderException e) {
						debug(e.toString());
					} catch (InvalidAlgorithmParameterException e) {
						debug(e.toString());
					}
					return null;
				}

				protected void onProgressUpdate(String... values) {
					debug(values[0]);
				}

				@Override
				protected void onPostExecute(Void result) {
					// TODO Auto-generated method stub
					progressdialog.dismiss();

				}

				@Override
				protected void onPreExecute() {
					progressdialog = ProgressDialog.show(getActivity(), "Please wait...", "Generating keys...");
				}

			}.execute();

		}

		private void firmaData() {
			String data = mInData.getText().toString();
			debug("Stringa da firmare:" + data);
			byte[] rawData = data.getBytes();

			// Accesso alla chiave
			KeyStore keyStore = initKeyStore();
			if (keyStore == null)
				return;

			KeyStore.PrivateKeyEntry keyEntry;
			byte[] signature = null;
			try {
				keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
				RSAPrivateKey privKey = (RSAPrivateKey) keyEntry.getPrivateKey();

				// Calcola firma
				Signature s = Signature.getInstance(SIGN_ALG);
				s.initSign(privKey);
				s.update(rawData);
				signature = s.sign();
			} catch (NoSuchAlgorithmException e) {
				debug(e.toString());
			} catch (UnrecoverableEntryException e) {
				debug(e.toString());
			} catch (KeyStoreException e) {
				debug(e.toString());
			} catch (InvalidKeyException e) {
				debug(e.toString());
			} catch (SignatureException e) {
				debug(e.toString());
			}

			// OK!
			if (signature != null) {
				String signData = Base64.encodeToString(signature, Base64.DEFAULT);
				mOutData.setText(signData);
				debug("Firma Calcolata:\n" + signData);
			}

		}

		private void verificaData() {
			byte[] data = mInData.getText().toString().getBytes();
			byte[] stringSignature = mOutData.getText().toString().getBytes();
			byte[] signature = null;
			try {
				signature = Base64.decode(stringSignature, Base64.DEFAULT);
			} catch (IllegalArgumentException e) {
				debug("String Base64 non valida");
				return;
			}

			// Accesso alla chiave
			KeyStore keyStore = initKeyStore();
			if (keyStore == null)
				return;

			KeyStore.PrivateKeyEntry keyEntry;
			boolean isSignValid = false;
			try {
				keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
				Certificate cert = keyEntry.getCertificate();

				// Verifica firma
				Signature s = Signature.getInstance(SIGN_ALG);
				s.initVerify(cert);
				s.update(data);
				isSignValid = s.verify(signature);
			} catch (NoSuchAlgorithmException e) {
				debug(e.toString());
			} catch (UnrecoverableEntryException e) {
				debug(e.toString());
			} catch (KeyStoreException e) {
				debug(e.toString());
			} catch (InvalidKeyException e) {
				debug(e.toString());
			} catch (SignatureException e) {
				debug(e.toString());
			}

			if (isSignValid){
				debug("Firma Valida");
				Toast.makeText(getActivity(), "Firma Valida", Toast.LENGTH_LONG).show();	
			}else{
				debug("Firma Errata!");
				Toast.makeText(getActivity(), "Firma Errata", Toast.LENGTH_LONG).show();	
			}
		}

		private KeyStore initKeyStore() {
			KeyStore keyStore = null;
			try {
				keyStore = KeyStore.getInstance("AndroidKeyStore");
				keyStore.load(null);

			} catch (KeyStoreException e) {
				debug("KeyStore Exception Error: " + e);
			} catch (NoSuchAlgorithmException e1) {
				debug(e1.toString());
			} catch (CertificateException e1) {
				debug(e1.toString());
			} catch (IOException e1) {
				debug(e1.toString());
			}
			return keyStore;
		}

		private void debug(String message) {
			mDebugText.append(message + "\n");
			Log.v(TAG, message);
		}
	}

}

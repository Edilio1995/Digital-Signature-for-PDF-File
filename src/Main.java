import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

import javafx.application.Application;
import javafx.application.HostServices;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.Window;

public class Main extends Application {

    @Override
    public void start(final Stage primaryStage) throws Exception {
    	 primaryStage.setTitle("Tool Digital Signature Financial Computing 2019");

    	    // Create the registration form pane
    	    GridPane gridPane = createRegistrationFormPane();
    	    // Create a scene with the registration form gridPane as the root node.
    	    addUIControls(gridPane, primaryStage);
            // Create a scene with registration form grid pane as the root node
            Scene scene = new Scene(gridPane, 700, 600);
            // Set the scene in primary stage	
            primaryStage.setScene(scene);
            
            primaryStage.show();
            
            
            
    }
    
    private void addUIControls(GridPane gridPane, Stage primaryStage) {
        // Add Header
        Label headerLabel = new Label("PDF DIGITAL SIGNATURE");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0,0,2,1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20,0));

        // Add Name Label
        Label certLabel = new Label("Input certificato : ");
        gridPane.add(certLabel, 0,1);

        // Add Name Text Field
        TextField certField = new TextField();
        certField.setPrefHeight(40);
        gridPane.add(certField, 1,1);


        // Add Password Label
        Label passwordLabel = new Label("Password certificato : ");
        gridPane.add(passwordLabel, 0, 2);

        // Add Password Field
        PasswordField passwordField = new PasswordField();
        passwordField.setPrefHeight(40);
        gridPane.add(passwordField, 1, 2);
        
     // Add Pdf origine Label
        Label originLabel = new Label("PDF Input : ");
        gridPane.add(originLabel, 0, 3);

        // Add Password Field
        TextField originField = new TextField();
        originField.setPrefHeight(40);
        gridPane.add(originField, 1, 3);
        
     // Add Pdf origine Label
        Label destinationLabel = new Label("PDF Output : ");
        gridPane.add(destinationLabel, 0, 4);

        // Add Password Field
        TextField destinationField = new TextField();
        destinationField.setPrefHeight(40);
        gridPane.add(destinationField, 1, 4);
        
 
        
     // Add Pdf origine Label
        Label nomeLabel = new Label("Nome esperto : ");
        gridPane.add(nomeLabel, 0, 5);
        TextField nomeField = new TextField();
        nomeField.setPrefHeight(40);  
        gridPane.add(nomeField, 1, 5);
        
        //
        Label ruoloLabel = new Label("Ruolo : ");
        gridPane.add(ruoloLabel, 0, 6);
        TextField ruoloField = new TextField();
        ruoloField.setPrefHeight(40);
        gridPane.add(ruoloField, 1, 6);
        
        //
        Label descrizioneLabel = new Label("Descrizione del lavoro : ");
        gridPane.add(descrizioneLabel, 0, 7);
        TextField descrizioneField = new TextField();
        descrizioneField.setPrefHeight(40);
        gridPane.add(descrizioneField, 1, 7);
        
        //FileChooser Button
        Button certButton = new Button("...");
        certButton.setPrefHeight(38);
        certButton.setPrefWidth(38);
        certButton.setOnAction(new EventHandler<ActionEvent>() {
			
			@Override
			public void handle(ActionEvent arg0) {
				FileChooser chooser = new FileChooser();
				File file = chooser.showOpenDialog(primaryStage);
				certField.setText(file.toString());
			}
		});
        gridPane.add(certButton, 2, 1);
        
        
        Button originButton = new Button("...");
        originButton.setPrefHeight(38);
        originButton.setPrefWidth(38);
        originButton.setOnAction(new EventHandler<ActionEvent>() {
			
			@Override
			public void handle(ActionEvent arg0) {
				FileChooser chooser = new FileChooser();
				File file = chooser.showOpenDialog(primaryStage);
				originField.setText(file.toString());
			}
		});
        gridPane.add(originButton, 2, 3);
        
        Button destinationButton = new Button("...");
        destinationButton.setPrefHeight(38);
        destinationButton.setPrefWidth(38);
        destinationButton.setOnAction(new EventHandler<ActionEvent>() {
			
			@Override
			public void handle(ActionEvent arg0) {
				FileChooser chooser = new FileChooser();
				FileChooser.ExtensionFilter fileExtensions = 
						  new FileChooser.ExtensionFilter(
						    "PDF", "*.pdf");

						chooser.getExtensionFilters().add(fileExtensions);
				File file = chooser.showSaveDialog(primaryStage);
				destinationField.setText(file.toString());
			}
		});
        gridPane.add(destinationButton, 2, 4);
        
        
        
        

        // Add Submit Button
        Button submitButton = new Button("Applica firma digitale");
        submitButton.setPrefHeight(40);
       
        submitButton.setDefaultButton(true);
        submitButton.setPrefWidth(180);
        submitButton.setFont(Font.font("Arial", FontWeight.BOLD, 14));
        submitButton.setOnAction(new EventHandler<ActionEvent>() {
			
			@Override
			public void handle(ActionEvent event) {
				if(certField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Compilare campo certificato");
		            return;
		        }
				if(passwordField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Compilare campo password");
		            return;
		        }
		        if(originField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Compilare campo per il pdf in input");
		            return;
		        }
		        if(destinationField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Specificare dove si vuole salvare il pdf firmato");
		            return;
		        }
		        if(nomeField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Specificare il nome dell'esperto");
		            return;
		        }
		        if(ruoloField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Specificare il ruolo");
		            return;
		        }
		        if(descrizioneField.getText().isEmpty()) {
		            showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
		            "Form Error!", "Specificare la descrizione");
		            return;
		        }
		        try {
		        	String auxInformation = "[Nome Esperto : " + nomeField.getText() + " , Ruolo : " + ruoloField.getText() + " , Descrizione del lavoro : " + descrizioneField.getText() + " ]";
		        	System.out.println("PASSWROD" + passwordField.getText());
		        	signPdf(certField.getText(),passwordField.getText().toCharArray(),originField.getText(),destinationField.getText(),auxInformation);
					showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), 
						        "Successo", "La firma al documento [" + destinationField.getText() + "] è stata applicata con successo");
						        HostServices hs =  getHostServices();
					            hs.showDocument(destinationField.getText());
				} catch (FileNotFoundException e) {
					showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
					        "Errore", "File non trovato");
					        HostServices hs =  getHostServices();
				            hs.showDocument(destinationField.getText());
					e.printStackTrace();
				} catch (IOException e) {
					showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
					        "Errore", "Errore generico, controllare password certificato");
					        HostServices hs =  getHostServices();
				            hs.showDocument(destinationField.getText());
					e.printStackTrace();
				} catch (GeneralSecurityException e) {
					showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
					        "Errore", "Errore di sicurezza!");
					        HostServices hs =  getHostServices();
				            hs.showDocument(destinationField.getText());
					e.printStackTrace();
				} catch (DocumentException e) {
					showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), 
					        "Errore", "Errore generale, qualcosa è andato storto con il documento in input");
					        HostServices hs =  getHostServices();
				            hs.showDocument(destinationField.getText());
					e.printStackTrace();
				} finally {
			       
		        }
			}
		});
        gridPane.add(submitButton, 0, 8, 2, 2);
        GridPane.setHalignment(submitButton, HPos.CENTER);
        GridPane.setMargin(submitButton, new Insets(0, 0, 0,0));
    }
    
    private void showAlert(Alert.AlertType alertType, Window owner, String title, String message) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.initOwner(owner);
        alert.show();
    }
    
    private void signPdf(String keystore, char[] password, String originField, String destinationField, String descrizione) throws FileNotFoundException, IOException, GeneralSecurityException, DocumentException {
    	BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        System.out.println("SOno la pass" + password.toString());
        ks.load(new FileInputStream(keystore), password);

        String alias = (String)ks.aliases().nextElement();

        PrivateKey pk = (PrivateKey) ks.getKey(alias, password);

        Certificate[] chain = ks.getCertificateChain(alias);
        
        PDF_Sign app = new PDF_Sign();

        app.sign(originField, String.format(destinationField, 1), chain, pk, DigestAlgorithms.SHA256,
        		provider.getName(), CryptoStandard.CMS, descrizione, "UNISA");

    }
    
    private GridPane createRegistrationFormPane() {
    	GridPane gridPane = new GridPane();
    	gridPane.setAlignment(Pos.CENTER);
    	gridPane.setPadding(new Insets(20,20,20,20));
    	//Setta il gap orizzontale fra colonne
    	gridPane.setHgap(1);
    	//Setta il gap verticale fra colonne
    	gridPane.setVgap(15);
    	
    	//Aggiungi vincoli colonne
    	ColumnConstraints columnOneConstraints = new ColumnConstraints(160,160,Double.MAX_VALUE);
    	columnOneConstraints.setHalignment(HPos.RIGHT);
    	
    	//I vincoli saranno applicati a tutte i nodi piazzati nella colonna 2
    	ColumnConstraints columnTwoConstrains = new ColumnConstraints(200,200, Double.MAX_VALUE);
    	columnTwoConstrains.setHgrow(Priority.ALWAYS);
    	 gridPane.getColumnConstraints().addAll(columnOneConstraints, columnTwoConstrains);
    	    
    	 return gridPane;
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}
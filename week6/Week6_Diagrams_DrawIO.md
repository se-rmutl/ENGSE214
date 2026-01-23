# Draw.io Diagrams for Week 6: Cryptography Basics

## 1. Alice-Bob-Eve Scenario (Eavesdropping)

```xml
<mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    
    <!-- Alice -->
    <mxCell id="alice" value="Alice&#xa;(Sender)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="120" y="300" width="60" height="120" as="geometry"/>
    </mxCell>
    
    <!-- Bob -->
    <mxCell id="bob" value="Bob&#xa;(Receiver)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="720" y="300" width="60" height="120" as="geometry"/>
    </mxCell>
    
    <!-- Eve -->
    <mxCell id="eve" value="Eve&#xa;(Eavesdropper)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
      <mxGeometry x="420" y="140" width="60" height="120" as="geometry"/>
    </mxCell>
    
    <!-- Message flow -->
    <mxCell id="message1" value="" style="endArrow=classic;html=1;strokeWidth=2;strokeColor=#d79b00;" edge="1" parent="1" source="alice" target="bob">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="messageLabel" value="Message: 'Hello Bob!'" style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];" vertex="1" connectable="0" parent="message1">
      <mxGeometry x="-0.1" y="2" relative="1" as="geometry">
        <mxPoint as="offset"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Eve eavesdropping -->
    <mxCell id="eavesdrop1" value="" style="endArrow=classic;html=1;strokeWidth=2;strokeColor=#b85450;dashed=1;" edge="1" parent="1" source="eve">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="450" y="260" as="sourcePoint"/>
        <mxPoint x="450" y="340" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <mxCell id="eaveLabel" value="Intercepts&#xa;Message" style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" connectable="0" parent="eavesdrop1">
      <mxGeometry x="-0.2" y="-1" relative="1" as="geometry">
        <mxPoint as="offset"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Threat indicators -->
    <mxCell id="threat1" value="❌ No Encryption&#xa;Eve can read message!" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
      <mxGeometry x="360" y="480" width="180" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="solution" value="✅ With Encryption&#xa;Eve cannot read!" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="360" y="560" width="180" height="60" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
```

## 2. Symmetric Encryption Diagram

```xml
<mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    
    <!-- Title -->
    <mxCell id="title" value="SYMMETRIC ENCRYPTION" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=20;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="360" y="40" width="300" height="40" as="geometry"/>
    </mxCell>
    
    <!-- Alice side -->
    <mxCell id="alice" value="Alice" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="120" y="200" width="50" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="plaintext1" value="Plaintext&#xa;'HELLO'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="100" y="360" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Encryption process -->
    <mxCell id="encrypt" value="Encrypt&#xa;with Key 🔑" style="rhombus;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="280" y="340" width="120" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow1" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="plaintext1" target="encrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Key (same) -->
    <mxCell id="key1" value="🔑 Key&#xa;(Same!)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="290" y="480" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="keyLine1" value="" style="endArrow=classic;html=1;strokeWidth=1;dashed=1;" edge="1" parent="1" source="key1" target="encrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Ciphertext -->
    <mxCell id="ciphertext" value="Ciphertext&#xa;'@#$%^'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
      <mxGeometry x="500" y="360" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow2" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="encrypt" target="ciphertext">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Decryption process -->
    <mxCell id="decrypt" value="Decrypt&#xa;with Key 🔑" style="rhombus;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="680" y="340" width="120" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow3" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="ciphertext" target="decrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Key 2 (same) -->
    <mxCell id="key2" value="🔑 Key&#xa;(Same!)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="690" y="480" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="keyLine2" value="" style="endArrow=classic;html=1;strokeWidth=1;dashed=1;" edge="1" parent="1" source="key2" target="decrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Bob side -->
    <mxCell id="bob" value="Bob" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="900" y="200" width="50" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="plaintext2" value="Plaintext&#xa;'HELLO'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="880" y="360" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow4" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="decrypt" target="plaintext2">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Note -->
    <mxCell id="note" value="⚠️ Problem: How to share the Key securely?" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="400" y="600" width="280" height="60" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
```

## 3. Asymmetric Encryption Diagram

```xml
<mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    
    <!-- Title -->
    <mxCell id="title" value="ASYMMETRIC ENCRYPTION (Public Key Cryptography)" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=20;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="240" y="40" width="600" height="40" as="geometry"/>
    </mxCell>
    
    <!-- Bob generates keys -->
    <mxCell id="bob1" value="Bob" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="900" y="120" width="50" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="keygen" value="Bob generates&#xa;Key Pair" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="760" y="140" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="publicKey" value="🔓 Public Key&#xa;(Share with everyone)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="760" y="240" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="privateKey" value="🔐 Private Key&#xa;(Keep secret!)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="900" y="240" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_keygen1" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="keygen" target="publicKey">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_keygen2" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="keygen" target="privateKey">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Alice encrypts -->
    <mxCell id="alice" value="Alice" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="120" y="360" width="50" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="plaintext" value="Plaintext&#xa;'Secret Message'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="95" y="520" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Bob sends public key to Alice -->
    <mxCell id="sendPubKey" value="Bob sends Public Key 🔓" style="endArrow=classic;html=1;strokeWidth=2;strokeColor=#9673a6;dashed=1;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="760" y="270" as="sourcePoint"/>
        <mxPoint x="280" y="380" as="targetPoint"/>
        <Array as="points">
          <mxPoint x="520" y="270"/>
          <mxPoint x="280" y="270"/>
        </Array>
      </mxGeometry>
    </mxCell>
    
    <!-- Encryption -->
    <mxCell id="encrypt" value="Encrypt&#xa;with Bob's&#xa;Public Key 🔓" style="rhombus;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="250" y="500" width="140" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_enc1" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="plaintext" target="encrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Ciphertext -->
    <mxCell id="ciphertext" value="Ciphertext&#xa;'X@7$Y#'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
      <mxGeometry x="480" y="520" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_enc2" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="encrypt" target="ciphertext">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Send to Bob -->
    <mxCell id="sendCipher" value="Send Ciphertext" style="endArrow=classic;html=1;strokeWidth=3;strokeColor=#b85450;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="580" y="550" as="sourcePoint"/>
        <mxPoint x="760" y="550" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Decryption -->
    <mxCell id="decrypt" value="Decrypt&#xa;with Bob's&#xa;Private Key 🔐" style="rhombus;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="780" y="500" width="140" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_dec1" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" target="decrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="760" y="550" as="sourcePoint"/>
        <mxPoint x="780" y="550" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Decrypted plaintext -->
    <mxCell id="plaintext2" value="Plaintext&#xa;'Secret Message'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="970" y="520" width="100" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_dec2" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="decrypt" target="plaintext2">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Note -->
    <mxCell id="note1" value="✅ Only Bob can decrypt (he has Private Key 🔐)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="380" y="680" width="340" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="note2" value="✅ No need to share Private Key!" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="380" y="760" width="340" height="40" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
```

## 4. PKI (Public Key Infrastructure) Architecture

```xml
<mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    
    <!-- Title -->
    <mxCell id="title" value="PKI - Public Key Infrastructure" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=24;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="360" y="40" width="400" height="40" as="geometry"/>
    </mxCell>
    
    <!-- Root CA -->
    <mxCell id="rootCA" value="Root CA&#xa;(Certificate Authority)&#xa;🏛️" style="ellipse;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;strokeWidth=3;" vertex="1" parent="1">
      <mxGeometry x="460" y="120" width="200" height="120" as="geometry"/>
    </mxCell>
    
    <!-- Intermediate CAs -->
    <mxCell id="intCA1" value="Intermediate CA 1" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="240" y="300" width="140" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="intCA2" value="Intermediate CA 2" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="490" y="300" width="140" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="intCA3" value="Intermediate CA 3" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="740" y="300" width="140" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Connections from Root to Intermediate -->
    <mxCell id="root_int1" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="rootCA" target="intCA1">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="root_int2" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="rootCA" target="intCA2">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="root_int3" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="rootCA" target="intCA3">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- End Entity Certificates -->
    <mxCell id="cert1" value="🌐 Web Server&#xa;www.example.com" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="140" y="460" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="cert2" value="📧 Email&#xa;user@example.com" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="280" y="460" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="cert3" value="🔐 VPN Gateway" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="430" y="460" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="cert4" value="📱 Mobile App" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="570" y="460" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="cert5" value="🔌 IoT Device" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="710" y="460" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="cert6" value="🖥️ User PC" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="850" y="460" width="120" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Connections from Intermediate to End Entity -->
    <mxCell id="int1_cert1" value="" style="endArrow=classic;html=1;strokeWidth=1;" edge="1" parent="1" source="intCA1" target="cert1">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="int1_cert2" value="" style="endArrow=classic;html=1;strokeWidth=1;" edge="1" parent="1" source="intCA1" target="cert2">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="int2_cert3" value="" style="endArrow=classic;html=1;strokeWidth=1;" edge="1" parent="1" source="intCA2" target="cert3">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="int2_cert4" value="" style="endArrow=classic;html=1;strokeWidth=1;" edge="1" parent="1" source="intCA2" target="cert4">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="int3_cert5" value="" style="endArrow=classic;html=1;strokeWidth=1;" edge="1" parent="1" source="intCA3" target="cert5">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="int3_cert6" value="" style="endArrow=classic;html=1;strokeWidth=1;" edge="1" parent="1" source="intCA3" target="cert6">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Certificate Chain -->
    <mxCell id="chain" value="Certificate Chain:&#xa;Root CA → Intermediate CA → End Entity Certificate" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="360" y="600" width="380" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Trust -->
    <mxCell id="trust" value="🔐 Root CA is pre-installed in OS/Browser (Trusted)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="360" y="680" width="380" height="40" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
```

## 5. Digital Signature Process

```xml
<mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    
    <!-- Title -->
    <mxCell id="title" value="DIGITAL SIGNATURE WORKFLOW" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=24;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="320" y="40" width="500" height="40" as="geometry"/>
    </mxCell>
    
    <!-- Signing Process (Alice) -->
    <mxCell id="signTitle" value="📝 SIGNING (Alice)" style="text;html=1;strokeColor=none;fillColor=#dae8fc;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=1;fontSize=16;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="80" y="120" width="280" height="40" as="geometry"/>
    </mxCell>
    
    <mxCell id="message1" value="Message&#xa;'I agree to pay $100'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="120" y="200" width="200" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="hash1" value="Hash Function&#xa;(SHA-256)" style="rhombus;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="150" y="300" width="140" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_hash1" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="message1" target="hash1">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="hashValue" value="Hash Value&#xa;'a7f3b2...'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="140" y="440" width="160" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_hash2" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="hash1" target="hashValue">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="sign" value="Encrypt with&#xa;Alice's Private Key 🔐" style="rhombus;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="140" y="540" width="160" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_sign" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="hashValue" target="sign">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="signature" value="✍️ Digital Signature&#xa;'x7y2...'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="140" y="680" width="160" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_sig" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="sign" target="signature">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Send to Bob -->
    <mxCell id="send" value="Send Message + Signature" style="endArrow=classic;html=1;strokeWidth=4;strokeColor=#d79b00;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="360" y="400" as="sourcePoint"/>
        <mxPoint x="680" y="400" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Verification Process (Bob) -->
    <mxCell id="verifyTitle" value="✅ VERIFICATION (Bob)" style="text;html=1;strokeColor=none;fillColor=#d5e8d4;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=1;fontSize=16;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="720" y="120" width="280" height="40" as="geometry"/>
    </mxCell>
    
    <mxCell id="receivedMsg" value="Received Message&#xa;'I agree to pay $100'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="760" y="200" width="200" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="receivedSig" value="Received Signature&#xa;'x7y2...'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="760" y="300" width="200" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Path 1: Hash received message -->
    <mxCell id="hash2" value="Hash Function&#xa;(SHA-256)" style="rhombus;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="620" y="420" width="140" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_hash3" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="receivedMsg" target="hash2">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="hashB" value="Hash B&#xa;'a7f3b2...'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="610" y="560" width="160" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_hashB" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="hash2" target="hashB">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Path 2: Decrypt signature -->
    <mxCell id="decrypt" value="Decrypt with&#xa;Alice's Public Key 🔓" style="rhombus;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="880" y="420" width="160" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_decrypt" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="receivedSig" target="decrypt">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="hashA" value="Hash A&#xa;'a7f3b2...'" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
      <mxGeometry x="880" y="560" width="160" height="60" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_hashA" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="decrypt" target="hashA">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Compare -->
    <mxCell id="compare" value="Compare&#xa;Hash A == Hash B ?" style="rhombus;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontSize=14;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="740" y="660" width="180" height="100" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_compA" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="hashA" target="compare">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_compB" value="" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1" source="hashB" target="compare">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <!-- Results -->
    <mxCell id="valid" value="✅ Valid!&#xa;- Alice sent this&#xa;- Not modified" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="600" y="800" width="140" height="80" as="geometry"/>
    </mxCell>
    
    <mxCell id="invalid" value="❌ Invalid!&#xa;- Tampered&#xa;- Wrong sender" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
      <mxGeometry x="920" y="800" width="140" height="80" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_valid" value="Match" style="endArrow=classic;html=1;strokeWidth=2;strokeColor=#82b366;" edge="1" parent="1" source="compare" target="valid">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
    
    <mxCell id="arrow_invalid" value="No Match" style="endArrow=classic;html=1;strokeWidth=2;strokeColor=#b85450;" edge="1" parent="1" source="compare" target="invalid">
      <mxGeometry width="50" height="50" relative="1" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
```

## 6. HTTPS/TLS Handshake

```xml
<mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    
    <!-- Title -->
    <mxCell id="title" value="HTTPS / TLS HANDSHAKE (Hybrid Encryption)" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=22;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="280" y="40" width="600" height="40" as="geometry"/>
    </mxCell>
    
    <!-- Browser -->
    <mxCell id="browser" value="Browser / Client" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="120" y="120" width="180" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Web Server -->
    <mxCell id="server" value="Web Server" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
      <mxGeometry x="820" y="120" width="180" height="60" as="geometry"/>
    </mxCell>
    
    <!-- Timeline -->
    <mxCell id="line1" value="" style="endArrow=none;dashed=1;html=1;strokeWidth=2;strokeColor=#6c8ebf;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="210" y="180" as="sourcePoint"/>
        <mxPoint x="210" y="780" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <mxCell id="line2" value="" style="endArrow=none;dashed=1;html=1;strokeWidth=2;strokeColor=#6c8ebf;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="910" y="180" as="sourcePoint"/>
        <mxPoint x="910" y="780" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Step 1 -->
    <mxCell id="step1" value="1. ClientHello&#xa;(Supported Ciphers)" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="210" y="220" as="sourcePoint"/>
        <mxPoint x="910" y="220" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Step 2 -->
    <mxCell id="step2" value="2. ServerHello + Certificate&#xa;(Public Key + CA Signature)" style="endArrow=classic;html=1;strokeWidth=2;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="910" y="280" as="sourcePoint"/>
        <mxPoint x="210" y="280" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Verify -->
    <mxCell id="verify" value="Verify Certificate" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
      <mxGeometry x="130" y="320" width="160" height="40" as="geometry"/>
    </mxCell>
    
    <mxCell id="verifyOK" value="✅ Valid" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
      <mxGeometry x="160" y="380" width="100" height="30" as="geometry"/>
    </mxCell>
    
    <!-- Step 3 -->
    <mxCell id="genKey" value="Generate Random&#xa;Session Key (AES)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="130" y="430" width="160" height="50" as="geometry"/>
    </mxCell>
    
    <mxCell id="step3" value="3. Encrypt Session Key&#xa;with Server's Public Key 🔓" style="endArrow=classic;html=1;strokeWidth=3;strokeColor=#d79b00;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="210" y="520" as="sourcePoint"/>
        <mxPoint x="910" y="520" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Server decrypts -->
    <mxCell id="decrypt" value="Decrypt Session Key&#xa;with Private Key 🔐" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;" vertex="1" parent="1">
      <mxGeometry x="830" y="540" width="160" height="50" as="geometry"/>
    </mxCell>
    
    <!-- Both have session key -->
    <mxCell id="bothHaveKey" value="🔑 Both sides now have the same Session Key!" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontSize=14;fontStyle=1" vertex="1" parent="1">
      <mxGeometry x="340" y="610" width="440" height="40" as="geometry"/>
    </mxCell>
    
    <!-- Step 4 -->
    <mxCell id="step4" value="4. Encrypted Data (AES-256)&#xa;Fast Symmetric Encryption ⚡" style="endArrow=classic;html=1;strokeWidth=3;strokeColor=#82b366;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="210" y="680" as="sourcePoint"/>
        <mxPoint x="910" y="680" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Step 5 -->
    <mxCell id="step5" value="5. Encrypted Response (AES-256)" style="endArrow=classic;html=1;strokeWidth=3;strokeColor=#82b366;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="910" y="730" as="sourcePoint"/>
        <mxPoint x="210" y="730" as="targetPoint"/>
      </mxGeometry>
    </mxCell>
    
    <!-- Summary -->
    <mxCell id="summary" value="✅ Hybrid Encryption:&#xa;• Asymmetric (RSA) for Key Exchange (Steps 1-3)&#xa;• Symmetric (AES) for Data Transfer (Steps 4-5)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;align=left;" vertex="1" parent="1">
      <mxGeometry x="340" y="780" width="440" height="80" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
```

---

## How to Use These Diagrams

1. **Import to draw.io:**
   - Go to https://app.diagrams.net/
   - File → Import from → XML
   - Copy & paste the XML code above

2. **Customize:**
   - Edit text, colors, positions as needed
   - Export as PNG/SVG for presentations

3. **Use in Teaching:**
   - Display during lecture
   - Include in slides
   - Print as handouts


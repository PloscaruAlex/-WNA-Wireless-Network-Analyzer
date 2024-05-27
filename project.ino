#include <TFT_eSPI.h>
#include <SPI.h>
#include <ezButton.h>
#include "banner_good.h"
#include <WiFi.h>

// settings for packet monitor
// #include "lwip/err.h"
// #include "driver/gpio.h"

// #include <Arduino.h>
// #include <TimeLib.h>
// #include "FS.h"
// #include <SD.h>
// #include "PCAP.h"

// #define CHANNEL 1
// #define FILENAME "esp32"
// #define SAVE_INTERVAL 30 //save new file every 30s
// #define CHANNEL_HOPPING true //if true it will scan on all channels
// #define MAX_CHANNEL 11 //(only necessary if channelHopping is true)
// #define HOP_INTERVAL 214 //in ms (only necessary if channelHopping is true)

// unsigned long lastTime = 0;
// unsigned long lastChannelChange = 0;
// int counter = 0;
// int ch = CHANNEL;
// bool fileOpen = false;

// PCAP pcap = PCAP();




// settings for deauth detector
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string>
#include <cstddef>
#include <Wire.h>
#include <Preferences.h>
using namespace std;

const uint16_t GRAY = 303131;
const uint16_t BLUE = 0x001f;
const uint16_t RED = 0xf800;
const uint16_t GREEN = 0x07e0;
const uint16_t BLACK = 0;
const uint16_t YELLOW = RED + GREEN;
const uint16_t CYAN = GREEN + BLUE;
const uint16_t MAGENTA = RED + BLUE;
const uint16_t WHITE = RED + BLUE + GREEN;
const uint16_t ORANGE = 0xfbe4;

#define MAX_CH 14
#define SNAP_LEN 2324 // max len of each received packet

#define MAX_X 240
#define MAX_Y 320

esp_err_t event_handler1(void *ctx, system_event_t *event) {
  return ESP_OK;
}

Preferences preferences1;

uint32_t lastDrawTime1;
uint32_t lastButtonTime1;
uint32_t tmpPacketCounter1;
uint32_t pkts11[MAX_X]; // here the packets per second will be saved
uint32_t deauths1 = 0; // deauth frames per second
unsigned int ch1 = 1; // current 802.11 channel
int rssiSum1;

//other settings

#define J_X_PIN  36
#define J_Y_PIN  39
#define J_SW 17
#define SCK  14
#define MISO  12
#define MOSI  13
#define CS  15
#define LED_PIN 32
#define BUZZER_PIN 33

// SPIClass spi = SPIClass(HSPI);

//joystick
int xValue, yValue, bValue; // normal value = 1800ish
ezButton button(J_SW);

TFT_eSPI tft = TFT_eSPI();

//menu 
const int numMenuItems = 3;
const char* menuItems[numMenuItems] = {"1.Packet Monitor", "2.Network Analyzer", "3.Detect Attack"};
int selectedItem = 0;
int function_mode = 0;
bool functioning = false;

void setup() {
  button.setDebounceTime(50);
  Serial.begin(9600);

  // spi.begin(SCK, MISO, MOSI, CS);

  // packet_monitor_setup();

  tft.init();
  tft.fillScreen(TFT_BLACK);
  tft.setSwapBytes(true);

  tft.pushImage(0, 0, 240, 320, banner_good);

  delay(4000);

  drawMenu();
}

void loop() {
    button.loop();

    if (functioning) {
      if (function_mode == 1) {
          // packet_monitor_loop();
          if (button.isPressed()) {
            function_mode = 0;
            functioning = false;
          }
      } else if (function_mode == 2) {
          network_analyzer_setup();
          network_analzyer_loop();
          if (button.isPressed()) {
            function_mode = 0;
            functioning = false;
          }
      } else if (function_mode == 3) {
          detectorSetup();
          detectorLoop();
          if (button.isPressed()) {
            function_mode = 0;
            functioning = false;
          }
      }
    } else {
      xValue = analogRead(J_X_PIN);
      yValue = analogRead(J_Y_PIN);
      bValue = button.getState();

      if (xValue < 900) {
        // Move down
        selectedItem = (selectedItem + 1) % numMenuItems;
        drawMenu();
        delay(500); // Debounce delay
      } else if (xValue > 2500) {
        // Move up
        selectedItem = (selectedItem - 1 + numMenuItems) % numMenuItems;
        drawMenu();
        delay(500); // Debounce delay
      }

      if (button.isPressed()) {
        function_mode = selectedItem + 1;
        functioning = true;
      }
    }

    delay(10);
}

void drawMenu() {
  tft.fillScreen(TFT_BLACK);
  for (int i = 0; i < numMenuItems; i++) {
    if (i == selectedItem) {
      tft.setTextColor(TFT_BLACK, TFT_CYAN);
    } else {
      tft.setTextColor(TFT_WHITE, TFT_BLACK);
    }
    tft.setCursor(10, 50 + i * 50);
    tft.setTextSize(2);
    tft.print(menuItems[i]);
  }
}

void network_analyzer_setup() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
}

void network_analzyer_loop() {
    int n = WiFi.scanNetworks();
    tft.fillScreen(TFT_BLACK);
    if (n == 0) {
        tft.setTextColor(TFT_BLACK, TFT_RED);
        tft.setCursor(20, 130);
        tft.setTextSize(3);
        tft.print("No networks");
        tft.setCursor(60, 160);
        tft.print("found!");
    } else {
        tft.setTextSize(2);
        tft.setTextColor(TFT_BLACK, TFT_CYAN);
        tft.setCursor(10, 10);
        tft.print(n);
        tft.println(" networks found");

        tft.setTextSize(1);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.setCursor(0, 30);
        tft.println("/ | SSID       | RSSI | CH | ENC_TYPE");

        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        for (int i = 1; i <= n; i++) {
          tft.setCursor(0, 50 + (i - 1) * 10);
          tft.print(String(i, 10) + ":");
        }

        int maxLength = 12;
        tft.setTextColor(TFT_CYAN, TFT_BLACK);
        for (int i = 0; i < n; i++) {
            tft.setCursor(20, 50 + i * 10);
            String ssid = WiFi.SSID(i);
            String truncatedSSID = ssid.substring(0, maxLength);
            tft.print(truncatedSSID.c_str());
        }

        tft.setTextColor(TFT_YELLOW, TFT_BLACK);
        for (int i = 0; i < n; i++) {
            tft.setCursor(100, 50 + i * 10);
            tft.print(WiFi.RSSI(i));
        }

        tft.setTextColor(TFT_RED, TFT_BLACK);
        for (int i = 0; i < n; i++) {
            tft.setCursor(140, 50 + i * 10);
            tft.println(WiFi.channel(i));
        }

        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        for (int i = 0; i < n; i++) {
            tft.setCursor(170, 50 + i * 10);
            switch (WiFi.encryptionType(i)) {
              case WIFI_AUTH_OPEN:
                  tft.print("OPEN");
                  break;
              case WIFI_AUTH_WEP:
                  tft.print("WEP");
                  break;
              case WIFI_AUTH_WPA_PSK:
                  tft.print("WPA");
                  break;
              case WIFI_AUTH_WPA2_PSK:
                  tft.print("WPA2");
                  break;
              case WIFI_AUTH_WPA_WPA2_PSK:
                  tft.print("WPA+WPA2");
                  break;
              case WIFI_AUTH_WPA2_ENTERPRISE:
                  tft.print("WPA2-EAP");
                  break;
              case WIFI_AUTH_WPA3_PSK:
                  tft.print("WPA3");
                  break;
              case WIFI_AUTH_WPA2_WPA3_PSK:
                  tft.print("WPA2+WPA3");
                  break;
              case WIFI_AUTH_WAPI_PSK:
                  tft.print("WAPI");
                  break;
              default:
                  tft.print("UNK");
            }
        }
      }

    WiFi.scanDelete();
    // Wait a bit before scanning again.
    delay(2000);
}

void drawScope(int px, int py, int w, int h) {
  uint16_t trace = ORANGE;

  int div = h / 8;

  float y0 = (cos(10));
  for (int x = 1; x < w; x++) {
    int adr = map(x, 0, w, 0, 1);
    float y = (tan(deauths1) * PI);
    tft.drawLine(px + x, py + (h / 2) + y0, px + x + 1, py + (h / 2) + y, trace);
    y0 = y;
  }
}

double getMultiplicator1() {
  uint32_t maxVal = 1;
  for (int i = 0; i < MAX_X; i++) {
    if (pkts11[i] > maxVal)
      maxVal = pkts11[i];
  }
  if (maxVal > MAX_Y)
    return (double)MAX_Y / (double)maxVal;
  else
    return 1;
}

void wifi_promiscuous1(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if (type == WIFI_PKT_MGMT && (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0))
    deauths1++;

  if (type == WIFI_PKT_MISC)
    return; // wrong packet type
  if (ctrl.sig_len > SNAP_LEN)
    return; // packet too long

  uint32_t packetLength = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT)
    packetLength -= 4;

  tmpPacketCounter1++;
  rssiSum1 += ctrl.rssi;
}

void setchannel(int newChannel) {
  ch1 = newChannel;
  if (ch1 > MAX_CH || ch1 < 1)
    ch1 = 1;

  preferences1.begin("packetmonitor32", false);
  preferences1.putUInt("channel", ch1);
  preferences1.end();

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(ch1, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous1);
  esp_wifi_set_promiscuous(true);
}

void draw1() {
  double multiplicator = getMultiplicator1();
  int len;
  int rssi;

  if (pkts11[MAX_X - 1] > 0)
    rssi = rssiSum1 / (int)pkts11[MAX_X - 1];
  else
    rssi = rssiSum1;

  for (int i = 0; i < MAX_X; i++) {
    len = pkts11[i] * multiplicator;
    if (i < MAX_X - 1)
      pkts11[i] = pkts11[i + 1];
  }
}

void detectorSetup() {
  Serial.begin(115200);

  tft.fillScreen(TFT_BLACK);

  preferences1.begin("packetmonitor32", false);
  ch1 = preferences1.getUInt("channel", 1);
  preferences1.end();

  nvs_flash_init();
  tcpip_adapter_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler1, NULL));
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  esp_wifi_set_channel(ch1, WIFI_SECOND_CHAN_NONE);

  tft.setTextWrap(false);
  tft.setTextSize(1);
  tft.setCursor(2, 2);
  tft.setTextColor(TFT_BLACK);
  tft.fillRect(0, 0, 128, 10, CYAN);
  tft.print("ch  |  graph  | value");
}

void detectorLoop() {
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous1);
  esp_wifi_set_promiscuous(true);

  uint32_t currentTime;

  while (true) {
    currentTime = millis();

    if (currentTime - lastDrawTime1 > 1000) {
      lastButtonTime1 = currentTime;

      pkts11[MAX_X - 1] = tmpPacketCounter1;

      draw1();

      Serial.print(ch1);
      Serial.print(":");
      Serial.println(deauths1);

      tmpPacketCounter1 = 0;
      deauths1 = 0;
      rssiSum1 = 0;
    }

    int newChannel = (ch1 % MAX_CH) + 1; // Cycle through channels 1-13

    ch1++;
    setchannel(ch1);
    if (ch1 < 1 || ch1 > 14)
      ch1 = 1;

    delay(1000);

    tft.setTextWrap(false);
    tft.setTextColor(TFT_CYAN);
    tft.setTextSize(1);

    for (int i = 1; i <= 14; i++) {
      tft.setCursor(0, 20 + (i - 1) * 10);
      tft.print(String(i, 10) + ":");
    }

    if (ch1 >= 1 && ch1 <= 14) {
      int y = 10 + (ch1 - 1) * 10;
      tft.fillRect(20, y, 130, 20, TFT_BLACK);
    }

    if (ch1 >= 1 && ch1 <= 14) {
      int startY = 5 + (ch1 - 1) * 10;
      drawScope(20, startY, 80, 40);
    }

    int lineSpacing = 10;
    int startY = 25;
    int endY = startY;

    for (int i = 0; i < 14; i++) {
      tft.drawLine(20, startY, 100, endY, WHITE);
      startY += lineSpacing;
      endY += lineSpacing;
    }

    tft.setTextSize(1);
    tft.setTextColor(TFT_CYAN);

    for (int i = 1; i <= 14; i++) {
      if (ch1 == i) {
        tft.setCursor(105, 20 + (i - 1) * 10);
        tft.print("[");
        tft.print(deauths1);
        tft.println(" ]");
      }
    }

    for (int i = 1; i <= 14; i++) {
      tft.setCursor(105, 20 + (i - 1) * 10);
      tft.print("[");
      tft.print("  ");
      tft.println("]");
    }

    if (deauths1 > 0) {
      digitalWrite(LED_PIN, HIGH);
      digitalWrite(BUZZER_PIN, HIGH);
    } else {
      digitalWrite(LED_PIN, LOW);
      digitalWrite(BUZZER_PIN, LOW);
    }
  }
}






// // packet monitor
// void sniffer(void *buf, wifi_promiscuous_pkt_type_t type){
  
//   if(fileOpen){
//     wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
//     wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
  
//     uint32_t timestamp = now(); //current timestamp 
//     uint32_t microseconds = (unsigned int)(micros() - millis() * 1000); //micro seconds offset (0 - 999)
//     pcap.newPacketSD(timestamp, microseconds, ctrl.sig_len, pkt->payload); //write packet to file
    
//   }
  
// }

// esp_err_t event_handler(void *ctx, system_event_t *event){ return ESP_OK; }


// /* opens a new file */
// void openFile(){

//   //searches for the next non-existent file name
//   int c = 0;
//   String filename = "/" + (String)FILENAME + ".pcap";
//   while(SD.open(filename)){
//     filename = "/" + (String)FILENAME + "_" + (String)c + ".pcap";
//     c++;
//   }
  
//   //set filename and open the file
//   pcap.filename = filename;
//   fileOpen = pcap.openFile(SD);

//   Serial.println("opened: "+filename);

//   //reset counter (counter for saving every X seconds)
//   counter = 0;
// }

// void packet_monitor_setup() {
//   if(!SD.begin(CS,spi,80000000)){
//     Serial.println("Card Mount Failed");
//     return;
//   }
  
//   uint8_t cardType = SD.cardType();
  
//   if(cardType == CARD_NONE){
//       Serial.println("No SD card attached");
//       return;
//   }

//   Serial.print("SD Card Type: ");
//   if(cardType == CARD_MMC){
//       Serial.println("MMC");
//   } else if(cardType == CARD_SD){
//       Serial.println("SDSC");
//   } else if(cardType == CARD_SDHC){
//       Serial.println("SDHC");
//   } else {
//       Serial.println("UNKNOWN");
//   }

//   int64_t cardSize = SD.cardSize() / (1024 * 1024);
//   Serial.printf("SD Card Size: %lluMB\n", cardSize);
    
//   openFile();

//   /* setup wifi */
//   nvs_flash_init();
//   tcpip_adapter_init();
//   ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
//   wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//   ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
//   ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
//   ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_AP) );  
//   ESP_ERROR_CHECK( esp_wifi_start() );
//   esp_wifi_set_promiscuous(true);
//   esp_wifi_set_promiscuous_rx_cb(sniffer);
//   wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
//   esp_wifi_set_channel(ch,secondCh);

//   Serial.println("Sniffer started!");
// }


// void packet_monitor_loop() {
//   tft.fillScreen(TFT_BLACK);
//   tft.setTextColor(TFT_BLACK, TFT_RED);
//   tft.setCursor(20, 130);
//   tft.setTextSize(3);
//   tft.print("Sniffing in");
//   tft.setCursor(30, 160);
//   tft.print("progress...");

//   unsigned long currentTime = millis();
  
//   /* Channel Hopping */
//   if(CHANNEL_HOPPING){
//     if(currentTime - lastChannelChange >= HOP_INTERVAL){
//       lastChannelChange = currentTime;
//       ch++; //increase channel
//       if(ch > MAX_CHANNEL) ch = 1;
//       wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
//       esp_wifi_set_channel(ch,secondCh);
//     }
//   }
  
// 	/* for every second */
//   if(fileOpen && currentTime - lastTime > 1000){
//     pcap.flushFile(); //save file
//     lastTime = currentTime; //update time
//     counter++; //add 1 to counter
//   }
//   /* when counter > 30s interval */
//   if(fileOpen && counter > SAVE_INTERVAL){
//     pcap.closeFile(); //save & close the file
//     fileOpen = false; //update flag
//     Serial.println("==================");
//     Serial.println(pcap.filename + " saved!");
//     Serial.println("==================");
//     openFile(); //open new file
//   }

// }


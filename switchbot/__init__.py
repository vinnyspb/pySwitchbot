"""Library to handle connection with Switchbot."""
from __future__ import annotations

import asyncio
import binascii
import logging
import uuid
from threading import Lock
import time
from typing import Any

from bleak import BleakScanner, BleakError
from bleak.backends.corebluetooth.client import BleakClientCoreBluetooth
from bleak.backends.device import BLEDevice

DEFAULT_RETRY_COUNT = 3
DEFAULT_RETRY_TIMEOUT = 1
DEFAULT_SCAN_TIMEOUT = 5

# Keys common to all device types
DEVICE_GET_BASIC_SETTINGS_KEY = "5702"
DEVICE_SET_MODE_KEY = "5703"
DEVICE_SET_EXTENDED_KEY = "570f"

# Bot keys
PRESS_KEY = "570100"
ON_KEY = "570101"
OFF_KEY = "570102"
DOWN_KEY = "570103"
UP_KEY = "570104"

# Curtain keys
OPEN_KEY = "570f450105ff00"  # 570F4501010100
CLOSE_KEY = "570f450105ff64"  # 570F4501010164
POSITION_KEY = "570F450105ff"  # +actual_position ex: 570F450105ff32 for 50%
STOP_KEY = "570F450100ff"
CURTAIN_EXT_SUM_KEY = "570f460401"
CURTAIN_EXT_ADV_KEY = "570f460402"
CURTAIN_EXT_CHAIN_INFO_KEY = "570f468101"

# Base key when encryption is set
KEY_PASSWORD_PREFIX = "571"

_LOGGER = logging.getLogger(__name__)
CONNECT_LOCK = Lock()


def _sb_uuid(comms_type: str = "service") -> uuid.UUID:
    """Return Switchbot UUID."""

    _uuid = {"tx": "002", "rx": "003", "service": "d00"}

    if comms_type in _uuid:
        return uuid.UUID(f"cba20{_uuid[comms_type]}-224d-11e6-9fb8-0002a5d5c51b")

    raise BleakError("Incorrect type, choose between: tx, rx or service")


def _process_wohand(data: bytes) -> dict[str, bool | int]:
    """Process woHand/Bot services data."""
    _switch_mode = bool(data[1] & 0b10000000)

    _bot_data = {
        "switchMode": _switch_mode,
        "isOn": not bool(data[1] & 0b01000000) if _switch_mode else False,
        "battery": data[2] & 0b01111111,
    }

    return _bot_data


def _process_btle_adv_data(dev: BLEDevice) -> dict[str, Any]:
    """Process bt le adv data."""
    _adv_data = {"mac_address": dev.address}
    _data = list(dev.metadata['service_data'].values())[0]

    supported_types: dict[str, dict[str, Any]] = {
        "H": {"modelName": "WoHand", "func": _process_wohand},
    }

    _model = chr(_data[0] & 0b01111111)
    _adv_data["isEncrypted"] = bool(_data[0] & 0b10000000)
    _adv_data["model"] = _model
    if _model in supported_types:
        _adv_data["data"] = supported_types[_model]["func"](_data)
        _adv_data["data"]["rssi"] = dev.rssi
        _adv_data["modelName"] = supported_types[_model]["modelName"]
    else:
        _adv_data["rawAdvData"] = list(dev.metadata['service_data'].values())[0]

    return _adv_data


class GetSwitchbotDevices:
    """Scan for all Switchbot devices and return by type."""

    def __init__(self, interface: int = 0) -> None:
        """Get switchbot devices class constructor."""
        self._interface = interface
        self._adv_data: dict[str, Any] = {}

    async def discover(
        self,
        retry: int = DEFAULT_RETRY_COUNT,
        scan_timeout: int = DEFAULT_SCAN_TIMEOUT,
        passive: bool = False,
        mac: str | None = None,
    ) -> dict[str, Any]:
        """Find switchbot devices and their advertisement data."""
        devices = None

        with CONNECT_LOCK:
            try:
                devices = await BleakScanner().discover(
                    scan_timeout
                )
            except BleakError:
                _LOGGER.error("Error scanning for switchbot devices", exc_info=True)

        if devices is None:
            if retry < 1:
                _LOGGER.error(
                    "Scanning for Switchbot devices failed. Stop trying", exc_info=True
                )
                return self._adv_data

            _LOGGER.warning(
                "Error scanning for Switchbot devices. Retrying (remaining: %d)",
                retry,
            )
            time.sleep(DEFAULT_RETRY_TIMEOUT)
            return await self.discover(
                retry=retry - 1,
                scan_timeout=scan_timeout,
                passive=passive,
                mac=mac,
            )

        for dev in devices:
            if str(_sb_uuid()) in dev.metadata['uuids']:
                if mac:
                    if dev.address.lower() == mac.lower():
                        self._adv_data[dev.address] = _process_btle_adv_data(dev)
                else:
                    self._adv_data[dev.address] = _process_btle_adv_data(dev)

        return self._adv_data

    async def get_bots(self) -> dict:
        """Return all WoHand/Bot devices with services data."""
        if not self._adv_data:
            await self.discover()

        _bot_devices = {
            device: data
            for device, data in self._adv_data.items()
            if data.get("model") == "H"
        }

        return _bot_devices

    async def get_device_data(self, mac: str) -> dict:
        """Return data for specific device."""
        if not self._adv_data:
            await self.discover()

        _switchbot_data = {
            device: data
            for device, data in self._adv_data.items()
            if data.get("mac_address") == mac
        }

        return _switchbot_data


class SwitchbotDevice(BleakClientCoreBluetooth):
    """Base Representation of a Switchbot Device."""

    def __init__(
        self,
        mac: str,
        password: str | None = None,
        interface: int = 0,
        **kwargs: Any,
    ) -> None:
        """Switchbot base class constructor."""
        BleakClientCoreBluetooth.__init__(
            self,
            address_or_ble_device=mac,
        )
        self._interface = interface
        self._mac = mac
        self._sb_adv_data: dict[str, Any] = {}
        self._scan_timeout: int = kwargs.pop("scan_timeout", DEFAULT_SCAN_TIMEOUT)
        self._retry_count: int = kwargs.pop("retry_count", DEFAULT_RETRY_COUNT)
        self._notifications = []
        if password is None or password == "":
            self._password_encoded = None
        else:
            self._password_encoded = "%x" % (
                binascii.crc32(password.encode("ascii")) & 0xFFFFFFFF
            )

    async def pair(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def unpair(self) -> bool:
        raise NotImplementedError

    # pylint: disable=arguments-differ
    async def _connect(self, retry: int) -> None:
        _LOGGER.debug("Connecting to Switchbot")

        if retry < 1:  # failsafe
            await self.disconnect()
            raise BleakError(
                "Failed to connect to peripheral %s" % self._mac
            )

        if not await self.connect():
            raise BleakError(
                        "Connection failed"
                    )

    def _commandkey(self, key: str) -> str:
        if self._password_encoded is None:
            return key
        key_action = key[3]
        key_suffix = key[4:]
        return KEY_PASSWORD_PREFIX + key_action + self._password_encoded + key_suffix

    async def _writekey(self, key: str) -> bool:
        _LOGGER.debug("Prepare to send")
        try:
            # hand = await self.read_gatt_char(_sb_uuid("tx"))
            _LOGGER.debug("Sending command, %s", key)
            await self.write_gatt_char(_sb_uuid("tx"), bytes.fromhex(key))
        except BleakError:
            _LOGGER.warning("Error sending command to Switchbot", exc_info=True)
            raise
        else:
            _LOGGER.info("Successfully sent command to Switchbot (MAC: %s)", self._mac)

        return True

    def _on_notify(self, sender: int, data: bytearray):
        print(f"{sender}: {data}")
        self._notifications.append(data)

    async def _subscribe(self) -> bool:
        _LOGGER.debug("Subscribe to notifications")
        try:
            await self.start_notify(_sb_uuid("rx"), self._on_notify)
        except BleakError:
            _LOGGER.warning(
                "Error while enabling notifications on Switchbot", exc_info=True
            )
            raise

        return True

    async def _readkey(self) -> bytes:
        _LOGGER.debug("Prepare to read notification from switchbot")
        while len(self._notifications) == 0:
            await asyncio.sleep(0.1)

        return self._notifications.pop()

    async def _sendcommand(self, key: str, retry: int) -> bytes:
        command = self._commandkey(key)
        send_success = False
        notify_msg = None
        _LOGGER.debug("Sending command to switchbot %s", command)

        with CONNECT_LOCK:
            try:
                await self._connect(retry)
                send_success = await self._subscribe()
            except BleakError:
                _LOGGER.warning("Error connecting to Switchbot", exc_info=True)
            else:
                try:
                    send_success = await self._writekey(command)
                except BleakError:
                    _LOGGER.warning(
                        "Error sending commands to Switchbot", exc_info=True
                    )
                else:
                    notify_msg = await self._readkey()
            finally:
                await self.disconnect()

        if notify_msg and send_success:
            if notify_msg == b"\x07":
                _LOGGER.error("Password required")
            elif notify_msg == b"\t":
                _LOGGER.error("Password incorrect")
            return notify_msg

        if retry < 1:
            _LOGGER.error(
                "Switchbot communication failed. Stopping trying", exc_info=True
            )
            return b"\x00"
        _LOGGER.warning("Cannot connect to Switchbot. Retrying (remaining: %d)", retry)
        time.sleep(DEFAULT_RETRY_TIMEOUT)
        return await self._sendcommand(key, retry - 1)

    def get_mac(self) -> str:
        """Return mac address of device."""
        return self._mac

    def get_battery_percent(self) -> Any:
        """Return device battery level in percent."""
        if not self._sb_adv_data.get("data"):
            return None
        return self._sb_adv_data["data"].get("battery")

    async def get_device_data(
        self,
        retry: int = DEFAULT_RETRY_COUNT,
        interface: int | None = None,
        passive: bool = False,
    ) -> dict[str, Any]:
        """Find switchbot devices and their advertisement data."""
        _interface: int = interface if interface else self._interface

        _data = await GetSwitchbotDevices(interface=_interface).discover(
            retry=retry,
            scan_timeout=self._scan_timeout,
            passive=passive,
            mac=self._mac,
        )

        if _data.get(self._mac):
            self._sb_adv_data = _data[self._mac]

        return self._sb_adv_data


class Switchbot(SwitchbotDevice):
    """Representation of a Switchbot."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Switchbot Bot/WoHand constructor."""
        super().__init__(*args, **kwargs)
        self._inverse: bool = kwargs.pop("inverse_mode", False)
        self._settings: dict[str, Any] = {}

    async def pair(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def unpair(self) -> bool:
        raise NotImplementedError

    async def update(self, interface: int | None = None, passive: bool = False) -> None:
        """Update mode, battery percent and state of device."""
        await self.get_device_data(
            retry=self._retry_count, interface=interface, passive=passive
        )

    async def turn_on(self) -> bool:
        """Turn device on."""
        result = await self._sendcommand(ON_KEY, self._retry_count)

        if result[0] == 1:
            return True

        if result[0] == 5:
            _LOGGER.debug("Bot is in press mode and doesn't have on state")
            return True

        return False

    async def turn_off(self) -> bool:
        """Turn device off."""
        result = await self._sendcommand(OFF_KEY, self._retry_count)
        if result[0] == 1:
            return True

        if result[0] == 5:
            _LOGGER.debug("Bot is in press mode and doesn't have off state")
            return True

        return False

    async def hand_up(self) -> bool:
        """Raise device arm."""
        result = await self._sendcommand(UP_KEY, self._retry_count)
        if result[0] == 1:
            return True

        if result[0] == 5:
            _LOGGER.debug("Bot is in press mode")
            return True

        return False

    async def hand_down(self) -> bool:
        """Lower device arm."""
        result = await self._sendcommand(DOWN_KEY, self._retry_count)
        if result[0] == 1:
            return True

        if result[0] == 5:
            _LOGGER.debug("Bot is in press mode")
            return True

        return False

    async def press(self) -> bool:
        """Press command to device."""
        result = await self._sendcommand(PRESS_KEY, self._retry_count)
        if result[0] == 1:
            return True

        if result[0] == 5:
            _LOGGER.debug("Bot is in switch mode")
            return True

        return False

    async def set_switch_mode(
        self, switch_mode: bool = False, strength: int = 100, inverse: bool = False
    ) -> bool:
        """Change bot mode."""
        mode_key = format(switch_mode, "b") + format(inverse, "b")
        strength_key = f"{strength:0{2}x}"  # to hex with padding to double-digit

        result = await self._sendcommand(
            DEVICE_SET_MODE_KEY + strength_key + mode_key, self._retry_count
        )

        if result[0] == 1:
            return True

        return False

    async def set_long_press(self, duration: int = 0) -> bool:
        """Set bot long press duration."""
        duration_key = f"{duration:0{2}x}"  # to hex with padding to double-digit

        result = await self._sendcommand(
            DEVICE_SET_EXTENDED_KEY + "08" + duration_key, self._retry_count
        )

        if result[0] == 1:
            return True

        return False

    async def get_basic_info(self) -> dict[str, Any] | None:
        """Get device basic settings."""
        _data = await self._sendcommand(
            key=DEVICE_GET_BASIC_SETTINGS_KEY, retry=self._retry_count
        )

        if _data in (b"\x07", b"\x00"):
            _LOGGER.error("Unsuccessful, please try again")
            return None

        self._settings = {
            "battery": _data[1],
            "firmware": _data[2] / 10.0,
            "strength": _data[3],
            "timers": _data[8],
            "switchMode": bool(_data[9] & 16),
            "inverseDirection": bool(_data[9] & 1),
            "holdSeconds": _data[10],
        }

        return self._settings

    def switch_mode(self) -> Any:
        """Return true or false from cache."""
        # To get actual position call update() first.
        if not self._sb_adv_data.get("data"):
            return None
        return self._sb_adv_data.get("switchMode")

    def is_on(self) -> Any:
        """Return switch state from cache."""
        # To get actual position call update() first.
        if not self._sb_adv_data.get("data"):
            return None

        if self._inverse:
            return not self._sb_adv_data["data"].get("isOn")

        return self._sb_adv_data["data"].get("isOn")

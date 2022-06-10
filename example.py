import asyncio

import switchbot


async def main():
    SWITCHBOT_MAC = '11111111-AAAA-DDDD-CCCC-AAAAA1111111'

    # initialize and fetch status
    bot = switchbot.Switchbot(mac=SWITCHBOT_MAC)
    await bot.update()
    print('bot status: ' + str(bot.is_on()))

    # switch the bot on and re-fetch the status
    await bot.turn_on()
    await bot.update()
    print('bot status: ' + str(bot.is_on()))


asyncio.run(main())

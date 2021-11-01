using System;
using Xunit;
using WopiHost.Core;

namespace WopiHost.Core.Tests
{
    public class WopiCoreTests
    {

        public WopiCoreTests()
        {
        }

        public void ToUnixTimestampTest()
        {
            // Arrange
            long ticks = 1635717257;
            DateTime dateTime = new(ticks);

            // Act

            long actual = Extensions.ToUnixTimestamp(dateTime.Date);

            // Assert
            Assert.Equal(ticks, actual);
        }

    }
}
